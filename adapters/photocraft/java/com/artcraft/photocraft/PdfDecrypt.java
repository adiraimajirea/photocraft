package com.artcraft.photocraft;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Removes password protection from a PDF so Android's {@link android.graphics.pdf.PdfRenderer}, which
 * only accepts a password on the newest Android versions, can render it.
 *
 * <p>Supports the standard security handler: RC4 40/128-bit (revisions 2 and 3), RC4 or AES-128 through
 * crypt filters (revision 4) and AES-256 (revisions 5 and 6). Either the user or the owner password
 * unlocks the file. The file is rewritten object by object with every string and stream decrypted and
 * a fresh cross-reference stream; nothing is held in memory but one object at a time, and the original
 * file is never modified.
 *
 * <p>No Android classes are used, so the class is testable on a desktop JVM.
 *
 * <pre>
 *   try (PdfDecrypt pdf = PdfDecrypt.open(file)) {
 *       if (pdf.authenticate(password)) pdf.writeDecrypted(unlockedFile);
 *   }
 * </pre>
 */
final class PdfDecrypt implements Closeable {

    /** The file is not encrypted, uses a scheme this class does not implement, or is too damaged to rewrite. */
    static final class Unsupported extends IOException {
        private static final long serialVersionUID = 1L;

        Unsupported(String message) { super(message); }

        Unsupported(String message, Throwable cause) { super(message, cause); }
    }

    private enum Method { NONE, RC4, AESV2, AESV3 }

    // ---- PDF object model (just enough to read, decrypt and re-emit an object) ----

    private static final Object NULL = new Object();

    private static final class Name {
        final String value; // raw bytes as ISO-8859-1 characters, '#xx' escapes resolved

        Name(String value) { this.value = value; }
    }

    private static final class Str {
        final byte[] bytes;

        Str(byte[] bytes) { this.bytes = bytes; }
    }

    private static final class Ref {
        final int num, gen;

        Ref(int num, int gen) { this.num = num; this.gen = gen; }
    }

    private static final class Keyword {
        final String value;

        Keyword(String value) { this.value = value; }
    }

    private static final class Real {
        final String text;

        Real(String text) { this.text = text; }
    }

    private static final class XEntry {
        final int type; // 0 free, 1 at file offset, 2 inside an object stream
        final long a;   // type 1: offset; type 2: object stream number
        final int b;    // type 1: generation; type 2: index within the stream

        XEntry(int type, long a, int b) { this.type = type; this.a = a; this.b = b; }
    }

    private static final byte[] PAD = {
            0x28, (byte) 0xBF, 0x4E, 0x5E, 0x4E, 0x75, (byte) 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, (byte) 0xFF, (byte) 0xFA,
            0x01, 0x08, 0x2E, 0x2E, 0x00, (byte) 0xB6, (byte) 0xD0, 0x68, 0x3E, (byte) 0x80, 0x2F, 0x0C, (byte) 0xA9,
            (byte) 0xFE, 0x64, 0x53, 0x69, 0x7A};

    private final RandomAccessFile file;
    private final ByteBuffer data;
    private final int size;
    private int base; // offset of "%PDF-" (offsets inside the file count from here)

    private final TreeMap<Integer, XEntry> xref = new TreeMap<>();
    private final Map<String, Object> trailer = new LinkedHashMap<>();

    // Encryption parameters, read from the /Encrypt dictionary.
    private int encObjNum = -1;
    private int version, revision, keyLen;
    private byte[] ownerEntry, userEntry, ownerKeyEntry, userKeyEntry, id0 = new byte[0];
    private int permissions;
    private boolean encryptMetadata = true;
    private Method stmMethod = Method.RC4, strMethod = Method.RC4;
    private byte[] fileKey;

    private PdfDecrypt(RandomAccessFile file, ByteBuffer data) {
        this.file = file;
        this.data = data;
        this.size = data.capacity();
    }

    /**
     * Read the structure and encryption settings of {@code pdf}. Does not check any password.
     *
     * @throws Unsupported when the file is not encrypted, uses an unsupported scheme or cannot be parsed
     */
    static PdfDecrypt open(File pdf) throws IOException {
        RandomAccessFile raf = new RandomAccessFile(pdf, "r");
        try {
            long length = raf.length();
            if (length > Integer.MAX_VALUE - 1024L) throw new Unsupported("The PDF is too large to unlock.");
            ByteBuffer map = raf.getChannel().map(FileChannel.MapMode.READ_ONLY, 0, length);
            PdfDecrypt decrypt = new PdfDecrypt(raf, map);
            decrypt.load();
            return decrypt;
        } catch (Unsupported e) {
            raf.close();
            throw e;
        } catch (IOException | RuntimeException e) {
            raf.close();
            throw new Unsupported("The PDF structure could not be read.", e);
        }
    }

    @Override
    public void close() throws IOException {
        file.close();
    }

    // ------------------------------------------------------------------------------------------
    // Password check
    // ------------------------------------------------------------------------------------------

    /** True (and the key is kept for {@link #writeDecrypted}) when {@code password} is the user or owner password. */
    boolean authenticate(String password) {
        try {
            if (revision >= 5) return authenticateAes256(password);
            byte[] pw = password.getBytes(StandardCharsets.ISO_8859_1);
            byte[] key = computeKey(pad(pw));
            if (checkUser(key)) { fileKey = key; return true; }
            key = computeKey(ownerToUserPassword(pw));
            if (checkUser(key)) { fileKey = key; return true; }
            return false;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static byte[] pad(byte[] password) {
        byte[] out = new byte[32];
        int n = Math.min(32, password.length);
        System.arraycopy(password, 0, out, 0, n);
        System.arraycopy(PAD, 0, out, n, 32 - n);
        return out;
    }

    /** Algorithm 2: the file key for a (padded) user password. */
    private byte[] computeKey(byte[] paddedUserPassword) throws GeneralSecurityException {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(paddedUserPassword);
        md5.update(ownerEntry, 0, 32);
        md5.update(new byte[]{(byte) permissions, (byte) (permissions >>> 8), (byte) (permissions >>> 16), (byte) (permissions >>> 24)});
        md5.update(id0);
        if (revision >= 4 && !encryptMetadata) md5.update(new byte[]{-1, -1, -1, -1});
        byte[] hash = md5.digest();
        if (revision >= 3) {
            for (int i = 0; i < 50; i++) {
                md5.update(hash, 0, keyLen);
                hash = md5.digest();
            }
        }
        return Arrays.copyOf(hash, keyLen);
    }

    /** Algorithms 4 and 5: does {@code key} reproduce the stored /U value? */
    private boolean checkUser(byte[] key) throws GeneralSecurityException {
        if (revision == 2) {
            return Arrays.equals(rc4(key, PAD), Arrays.copyOf(userEntry, 32));
        }
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(PAD);
        md5.update(id0);
        byte[] x = rc4(key, md5.digest());
        for (int i = 1; i <= 19; i++) x = rc4(xorKey(key, i), x);
        return Arrays.equals(Arrays.copyOf(x, 16), Arrays.copyOf(userEntry, 16));
    }

    /** Algorithm 7: recover the padded user password from /O using the owner password. */
    private byte[] ownerToUserPassword(byte[] ownerPassword) throws GeneralSecurityException {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] hash = md5.digest(pad(ownerPassword));
        if (revision >= 3) {
            for (int i = 0; i < 50; i++) hash = md5.digest(hash);
        }
        byte[] key = Arrays.copyOf(hash, keyLen);
        byte[] result = Arrays.copyOf(ownerEntry, 32);
        if (revision == 2) return rc4(key, result);
        for (int i = 19; i >= 0; i--) result = rc4(xorKey(key, i), result);
        return result;
    }

    private static byte[] xorKey(byte[] key, int value) {
        byte[] out = new byte[key.length];
        for (int i = 0; i < key.length; i++) out[i] = (byte) (key[i] ^ value);
        return out;
    }

    private boolean authenticateAes256(String password) throws GeneralSecurityException {
        byte[] pw = password.getBytes(StandardCharsets.UTF_8);
        if (pw.length > 127) pw = Arrays.copyOf(pw, 127);
        byte[] zeroIv = new byte[16];
        // User password.
        if (Arrays.equals(hashAes256(pw, Arrays.copyOfRange(userEntry, 32, 40), null), Arrays.copyOf(userEntry, 32))) {
            byte[] intermediate = hashAes256(pw, Arrays.copyOfRange(userEntry, 40, 48), null);
            fileKey = aesCbc(false, intermediate, zeroIv, userKeyEntry, 0, 32);
            return true;
        }
        // Owner password: its hashes also cover the first 48 bytes of /U.
        byte[] u48 = Arrays.copyOf(userEntry, 48);
        if (Arrays.equals(hashAes256(pw, Arrays.copyOfRange(ownerEntry, 32, 40), u48), Arrays.copyOf(ownerEntry, 32))) {
            byte[] intermediate = hashAes256(pw, Arrays.copyOfRange(ownerEntry, 40, 48), u48);
            fileKey = aesCbc(false, intermediate, zeroIv, ownerKeyEntry, 0, 32);
            return true;
        }
        return false;
    }

    /** Revision 5: SHA-256. Revision 6: the iterated hash of ISO 32000-2 algorithm 2.B. */
    private byte[] hashAes256(byte[] password, byte[] salt, byte[] udata) throws GeneralSecurityException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(password);
        sha256.update(salt);
        if (udata != null) sha256.update(udata);
        byte[] k = sha256.digest();
        if (revision == 5) return k;
        byte[] e = new byte[]{0};
        int round = 0;
        while (round < 64 || (e[e.length - 1] & 0xFF) > round - 32) {
            int udataLength = udata == null ? 0 : udata.length;
            byte[] unit = new byte[password.length + k.length + udataLength];
            System.arraycopy(password, 0, unit, 0, password.length);
            System.arraycopy(k, 0, unit, password.length, k.length);
            if (udata != null) System.arraycopy(udata, 0, unit, password.length + k.length, udataLength);
            byte[] repeated = new byte[unit.length * 64];
            for (int i = 0; i < 64; i++) System.arraycopy(unit, 0, repeated, i * unit.length, unit.length);
            e = aesCbc(true, Arrays.copyOf(k, 16), Arrays.copyOfRange(k, 16, 32), repeated, 0, repeated.length);
            int mod = 0;
            for (int i = 0; i < 16; i++) mod += e[i] & 0xFF;
            String algorithm = mod % 3 == 0 ? "SHA-256" : mod % 3 == 1 ? "SHA-384" : "SHA-512";
            k = MessageDigest.getInstance(algorithm).digest(e);
            round++;
        }
        return Arrays.copyOf(k, 32);
    }

    // ------------------------------------------------------------------------------------------
    // Ciphers
    // ------------------------------------------------------------------------------------------

    private static byte[] rc4(byte[] key, byte[] in) {
        int[] s = new int[256];
        for (int i = 0; i < 256; i++) s[i] = i;
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + s[i] + (key[i % key.length] & 0xFF)) & 0xFF;
            int t = s[i]; s[i] = s[j]; s[j] = t;
        }
        byte[] out = new byte[in.length];
        int a = 0, b = 0;
        for (int k = 0; k < in.length; k++) {
            a = (a + 1) & 0xFF;
            b = (b + s[a]) & 0xFF;
            int t = s[a]; s[a] = s[b]; s[b] = t;
            out[k] = (byte) (in[k] ^ s[(s[a] + s[b]) & 0xFF]);
        }
        return out;
    }

    private static void rc4InPlace(byte[] key, byte[] buf) {
        int[] s = new int[256];
        for (int i = 0; i < 256; i++) s[i] = i;
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + s[i] + (key[i % key.length] & 0xFF)) & 0xFF;
            int t = s[i]; s[i] = s[j]; s[j] = t;
        }
        int a = 0, b = 0;
        for (int k = 0; k < buf.length; k++) {
            a = (a + 1) & 0xFF;
            b = (b + s[a]) & 0xFF;
            int t = s[a]; s[a] = s[b]; s[b] = t;
            buf[k] ^= (byte) s[(s[a] + s[b]) & 0xFF];
        }
    }

    private static byte[] aesCbc(boolean encrypt, byte[] key, byte[] iv, byte[] in, int offset, int length)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(in, offset, length);
    }

    /** Per-object key (algorithm 1); AES-256 uses the file key as is. */
    private byte[] objectKey(int num, int gen, Method method) throws GeneralSecurityException {
        if (method == Method.AESV3) return fileKey;
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(fileKey);
        md5.update(new byte[]{(byte) num, (byte) (num >>> 8), (byte) (num >>> 16), (byte) gen, (byte) (gen >>> 8)});
        if (method == Method.AESV2) md5.update(new byte[]{0x73, 0x41, 0x6C, 0x54}); // "sAlT"
        return Arrays.copyOf(md5.digest(), Math.min(fileKey.length + 5, 16));
    }

    private byte[] decryptBytes(Method method, byte[] in, int num, int gen) {
        if (method == Method.NONE) return in;
        try {
            byte[] key = objectKey(num, gen, method);
            if (method == Method.RC4) return rc4(key, in);
            if (in.length < 16) return new byte[0];
            int blocks = (in.length - 16) / 16 * 16;
            if (blocks == 0) return new byte[0];
            byte[] plain = aesCbc(false, key, Arrays.copyOf(in, 16), in, 16, blocks);
            int pad = plain[plain.length - 1] & 0xFF;
            return pad >= 1 && pad <= 16 && pad <= plain.length ? Arrays.copyOf(plain, plain.length - pad) : plain;
        } catch (GeneralSecurityException e) {
            return new byte[0];
        }
    }

    /**
     * Decrypt a (possibly very large) stream inside {@code buf}, so the work needs no second copy of it.
     *
     * @return the length of the plain data, which starts at index 0 of {@code buf}
     */
    private int decryptInPlace(Method method, byte[] buf, int num, int gen) {
        if (method == Method.NONE) return buf.length;
        try {
            byte[] key = objectKey(num, gen, method);
            if (method == Method.RC4) {
                rc4InPlace(key, buf);
                return buf.length;
            }
            int blocks = buf.length < 16 ? 0 : (buf.length - 16) / 16 * 16;
            if (blocks == 0) return 0;
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(Arrays.copyOf(buf, 16)));
            // The cipher accepts input and output in one array (it is copy-safe), reading ahead of where it writes.
            int produced = cipher.doFinal(buf, 16, blocks, buf, 0);
            int pad = buf[produced - 1] & 0xFF;
            return pad >= 1 && pad <= 16 && pad <= produced ? produced - pad : produced;
        } catch (GeneralSecurityException e) {
            return 0;
        }
    }

    // ------------------------------------------------------------------------------------------
    // Lexer / parser
    // ------------------------------------------------------------------------------------------

    private static boolean isWhite(int c) {
        return c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32;
    }

    private static boolean isDelimiter(int c) {
        return c == '(' || c == ')' || c == '<' || c == '>' || c == '[' || c == ']' || c == '{' || c == '}' || c == '/' || c == '%';
    }

    private static boolean allDigits(String s) {
        if (s.isEmpty() || s.length() > 10) return false;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) < '0' || s.charAt(i) > '9') return false;
        return true;
    }

    private Parser at(long fileOffset) throws Unsupported {
        long absolute = fileOffset + base;
        if (fileOffset < 0 || absolute >= size) throw new Unsupported("The PDF structure is damaged.");
        return new Parser((int) absolute);
    }

    private final class Parser {
        int pos;

        Parser(int pos) { this.pos = pos; }

        int peek() { return pos < size ? data.get(pos) & 0xFF : -1; }

        int peekAt(int index) { return index < size ? data.get(index) & 0xFF : -1; }

        void skipWhite() {
            for (;;) {
                int c = peek();
                if (c < 0) return;
                if (isWhite(c)) {
                    pos++;
                } else if (c == '%') {
                    while (c >= 0 && c != 10 && c != 13) { pos++; c = peek(); }
                } else {
                    return;
                }
            }
        }

        boolean matches(String word) {
            for (int i = 0; i < word.length(); i++) if (peekAt(pos + i) != word.charAt(i)) return false;
            return true;
        }

        String readToken() {
            StringBuilder sb = new StringBuilder();
            for (;;) {
                int c = peek();
                if (c < 0 || isWhite(c) || isDelimiter(c)) break;
                sb.append((char) c);
                pos++;
            }
            return sb.toString();
        }

        long readLong() throws Unsupported {
            skipWhite();
            String token = readToken();
            try {
                return Long.parseLong(token);
            } catch (NumberFormatException e) {
                throw new Unsupported("The PDF structure is damaged.");
            }
        }

        String readName() {
            StringBuilder sb = new StringBuilder();
            for (;;) {
                int c = peek();
                if (c < 0 || isWhite(c) || isDelimiter(c)) break;
                pos++;
                if (c == '#' && hex(peekAt(pos)) >= 0 && hex(peekAt(pos + 1)) >= 0) {
                    c = hex(peekAt(pos)) * 16 + hex(peekAt(pos + 1));
                    pos += 2;
                }
                sb.append((char) c);
            }
            return sb.toString();
        }

        byte[] readLiteralString() throws Unsupported {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int depth = 1;
            for (;;) {
                int c = peek();
                if (c < 0) throw new Unsupported("The PDF structure is damaged.");
                pos++;
                if (c == '(') {
                    depth++;
                    out.write(c);
                } else if (c == ')') {
                    if (--depth == 0) return out.toByteArray();
                    out.write(c);
                } else if (c == '\\') {
                    int n = peek();
                    if (n < 0) throw new Unsupported("The PDF structure is damaged.");
                    pos++;
                    switch (n) {
                        case 'n': out.write(10); break;
                        case 'r': out.write(13); break;
                        case 't': out.write(9); break;
                        case 'b': out.write(8); break;
                        case 'f': out.write(12); break;
                        case 13: if (peek() == 10) pos++; break; // line continuation
                        case 10: break;
                        default:
                            if (n >= '0' && n <= '7') {
                                int value = n - '0';
                                for (int i = 0; i < 2; i++) {
                                    int d = peek();
                                    if (d < '0' || d > '7') break;
                                    value = value * 8 + (d - '0');
                                    pos++;
                                }
                                out.write(value & 0xFF);
                            } else {
                                out.write(n);
                            }
                    }
                } else if (c == 13) {
                    if (peek() == 10) pos++;
                    out.write(10); // a bare end-of-line inside a string reads as LF
                } else {
                    out.write(c);
                }
            }
        }

        byte[] readHexString() throws Unsupported {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int high = -1;
            for (;;) {
                int c = peek();
                if (c < 0) throw new Unsupported("The PDF structure is damaged.");
                pos++;
                if (c == '>') break;
                int d = hex(c);
                if (d < 0) continue;
                if (high < 0) {
                    high = d;
                } else {
                    out.write(high * 16 + d);
                    high = -1;
                }
            }
            if (high >= 0) out.write(high * 16);
            return out.toByteArray();
        }

        Object parseValue(int depth) throws IOException {
            if (depth > 64) throw new Unsupported("The PDF structure is too deeply nested.");
            skipWhite();
            int c = peek();
            if (c < 0) throw new Unsupported("The PDF structure is damaged.");
            switch (c) {
                case '/':
                    pos++;
                    return new Name(readName());
                case '(':
                    pos++;
                    return new Str(readLiteralString());
                case '<':
                    if (peekAt(pos + 1) == '<') {
                        pos += 2;
                        return readDictionary(depth);
                    }
                    pos++;
                    return new Str(readHexString());
                case '[': {
                    pos++;
                    List<Object> list = new ArrayList<>();
                    for (;;) {
                        skipWhite();
                        int n = peek();
                        if (n < 0) throw new Unsupported("The PDF structure is damaged.");
                        if (n == ']') { pos++; return list; }
                        Object item = parseValue(depth + 1);
                        if (item instanceof Keyword) throw new Unsupported("The PDF structure is damaged.");
                        list.add(item);
                    }
                }
                case ')': case '>': case ']': case '{': case '}':
                    throw new Unsupported("The PDF structure is damaged.");
                default:
                    break;
            }
            String token = readToken();
            if (token.isEmpty()) throw new Unsupported("The PDF structure is damaged.");
            char first = token.charAt(0);
            if ((first >= '0' && first <= '9') || first == '+' || first == '-' || first == '.') {
                if (allDigits(token)) {
                    long number = Long.parseLong(token);
                    int save = pos;
                    skipWhite();
                    int n = peek();
                    if (n >= '0' && n <= '9') {
                        String gen = readToken();
                        if (allDigits(gen)) {
                            skipWhite();
                            if (peek() == 'R') {
                                int next = peekAt(pos + 1);
                                if (next < 0 || isWhite(next) || isDelimiter(next)) {
                                    pos++;
                                    return new Ref((int) number, (int) Long.parseLong(gen));
                                }
                            }
                        }
                    }
                    pos = save;
                    return Long.valueOf(number);
                }
                try {
                    return Long.valueOf(Long.parseLong(token));
                } catch (NumberFormatException e) {
                    return new Real(token);
                }
            }
            if (token.equals("true")) return Boolean.TRUE;
            if (token.equals("false")) return Boolean.FALSE;
            if (token.equals("null")) return NULL;
            return new Keyword(token);
        }

        Map<String, Object> readDictionary(int depth) throws IOException {
            Map<String, Object> map = new LinkedHashMap<>();
            for (;;) {
                skipWhite();
                int c = peek();
                if (c < 0) throw new Unsupported("The PDF structure is damaged.");
                if (c == '>' && peekAt(pos + 1) == '>') { pos += 2; return map; }
                if (c != '/') throw new Unsupported("The PDF structure is damaged.");
                pos++;
                String key = readName();
                skipWhite();
                if (peek() == '>' && peekAt(pos + 1) == '>') { map.put(key, NULL); continue; }
                Object value = parseValue(depth + 1);
                if (value instanceof Keyword) throw new Unsupported("The PDF structure is damaged.");
                map.put(key, value);
            }
        }
    }

    private static int hex(int c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    // ------------------------------------------------------------------------------------------
    // File structure
    // ------------------------------------------------------------------------------------------

    private void load() throws IOException {
        base = 0;
        int limit = Math.min(size - 5, 1024);
        for (int i = 0; i <= limit; i++) {
            if (data.get(i) == '%' && data.get(i + 1) == 'P' && data.get(i + 2) == 'D' && data.get(i + 3) == 'F' && data.get(i + 4) == '-') {
                base = i;
                break;
            }
        }
        readXrefChain(findStartXref());
        if (!(trailer.get("Root") instanceof Ref)) throw new Unsupported("The PDF has no document catalog.");
        Object encrypt = trailer.get("Encrypt");
        if (encrypt == null) throw new Unsupported("The PDF is not password-protected.");
        if (encrypt instanceof Ref) {
            encObjNum = ((Ref) encrypt).num;
            encrypt = readIndirect(encObjNum);
        }
        if (!(encrypt instanceof Map)) throw new Unsupported("The PDF encryption settings are damaged.");
        readEncryption(castMap(encrypt));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object o) {
        return (Map<String, Object>) o;
    }

    private long findStartXref() throws IOException {
        byte[] word = "startxref".getBytes(StandardCharsets.ISO_8859_1);
        for (int i = size - word.length; i >= 0 && i >= size - 4096; i--) {
            boolean match = true;
            for (int k = 0; k < word.length && match; k++) match = data.get(i + k) == word[k];
            if (match) {
                Parser p = new Parser(i + word.length);
                return p.readLong();
            }
        }
        throw new Unsupported("The PDF has no cross-reference table.");
    }

    private void readXrefChain(long start) throws IOException {
        Set<Long> seen = new HashSet<>();
        ArrayDeque<Long> pending = new ArrayDeque<>();
        pending.add(start);
        while (!pending.isEmpty()) {
            long offset = pending.poll();
            if (offset < 0 || !seen.add(offset)) continue;
            Map<String, Object> dict = readXrefSection(offset);
            for (Map.Entry<String, Object> e : dict.entrySet()) trailer.putIfAbsent(e.getKey(), e.getValue());
            Object prev = dict.get("Prev");
            if (prev instanceof Long) pending.add((Long) prev);
            else if (prev instanceof Real) pending.add((long) Double.parseDouble(((Real) prev).text));
        }
    }

    private Map<String, Object> readXrefSection(long offset) throws IOException {
        Parser p = at(offset);
        p.skipWhite();
        if (p.matches("xref")) {
            p.pos += 4;
            for (;;) {
                p.skipWhite();
                if (p.matches("trailer")) { p.pos += 7; break; }
                long first = p.readLong();
                long count = p.readLong();
                boolean shifted = false;
                for (long i = 0; i < count; i++) {
                    long entryOffset = p.readLong();
                    int gen = (int) p.readLong();
                    p.skipWhite();
                    boolean inUse = p.readToken().equals("n");
                    // Some writers start the first subsection at 1 although it begins with the free head entry.
                    if (i == 0 && first == 1 && !inUse && gen == 65535 && entryOffset == 0) shifted = true;
                    int num = (int) (first + i - (shifted ? 1 : 0));
                    xref.putIfAbsent(num, inUse ? new XEntry(1, entryOffset, gen) : new XEntry(0, 0, gen));
                }
            }
            Object value = p.parseValue(0);
            if (!(value instanceof Map)) throw new Unsupported("The PDF structure is damaged.");
            Map<String, Object> dict = castMap(value);
            Object hybrid = dict.get("XRefStm");
            if (hybrid instanceof Long) readXrefStream((Long) hybrid); // hybrid file: objects kept in object streams
            return dict;
        }
        return readXrefStream(offset);
    }

    private Map<String, Object> readXrefStream(long offset) throws IOException {
        Parser p = at(offset);
        p.readLong();
        p.readLong();
        p.skipWhite();
        if (!p.readToken().equals("obj")) throw new Unsupported("The PDF structure is damaged.");
        Object value = p.parseValue(0);
        if (!(value instanceof Map)) throw new Unsupported("The PDF structure is damaged.");
        Map<String, Object> dict = castMap(value);
        p.skipWhite();
        if (!p.readToken().equals("stream")) throw new Unsupported("The PDF structure is damaged.");
        byte[] raw = readStreamBytes(p, dict);
        byte[] table = decodeFlate(raw, dict);
        List<Object> w = asList(dict.get("W"));
        if (w == null || w.size() < 3) throw new Unsupported("The PDF structure is damaged.");
        int w0 = asInt(w.get(0)), w1 = asInt(w.get(1)), w2 = asInt(w.get(2));
        int rowSize = w0 + w1 + w2;
        if (rowSize <= 0 || w1 > 8 || w2 > 8) throw new Unsupported("The PDF structure is damaged.");
        List<Object> index = asList(dict.get("Index"));
        if (index == null) index = Arrays.<Object>asList(Long.valueOf(0), dict.get("Size"));
        int row = 0;
        for (int s = 0; s + 1 < index.size(); s += 2) {
            long first = asLong(index.get(s)), count = asLong(index.get(s + 1));
            for (long i = 0; i < count; i++, row++) {
                int at = row * rowSize;
                if (at + rowSize > table.length) return dict;
                long type = w0 == 0 ? 1 : number(table, at, w0);
                long f2 = number(table, at + w0, w1);
                long f3 = number(table, at + w0 + w1, w2);
                int num = (int) (first + i);
                if (type == 1) xref.putIfAbsent(num, new XEntry(1, f2, (int) f3));
                else if (type == 2) xref.putIfAbsent(num, new XEntry(2, f2, (int) f3));
                else xref.putIfAbsent(num, new XEntry(0, 0, (int) f3));
            }
        }
        return dict;
    }

    private static long number(byte[] b, int at, int width) {
        long v = 0;
        for (int i = 0; i < width; i++) v = (v << 8) | (b[at + i] & 0xFF);
        return v;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> asList(Object o) {
        return o instanceof List ? (List<Object>) o : null;
    }

    private static long asLong(Object o) throws Unsupported {
        if (o instanceof Long) return (Long) o;
        if (o instanceof Real) return (long) Double.parseDouble(((Real) o).text);
        throw new Unsupported("The PDF structure is damaged.");
    }

    private static int asInt(Object o) throws Unsupported {
        return (int) asLong(o);
    }

    private static String nameOf(Object o) {
        return o instanceof Name ? ((Name) o).value : null;
    }

    /** Read the data of a stream whose dictionary was just parsed; {@code p} sits right after the word "stream". */
    private byte[] readStreamBytes(Parser p, Map<String, Object> dict) throws IOException {
        int c = p.peek();
        if (c == 13) {
            p.pos++;
            if (p.peek() == 10) p.pos++;
        } else if (c == 10) {
            p.pos++;
        }
        int start = p.pos;
        long length = -1;
        Object declared = dict.get("Length");
        if (declared instanceof Long) {
            length = (Long) declared;
        } else if (declared instanceof Ref) {
            try {
                Object resolved = readIndirect(((Ref) declared).num);
                if (resolved instanceof Long) length = (Long) resolved;
            } catch (IOException | RuntimeException e) {
                length = -1;
            }
        }
        int end = -1;
        if (length >= 0 && start + length <= size) {
            Parser q = new Parser((int) (start + length));
            q.skipWhite();
            if (q.matches("endstream")) end = (int) (start + length);
        }
        if (end < 0) { // wrong or missing /Length: look for the closing keyword instead
            end = indexOf("endstream", start);
            if (end < 0) throw new Unsupported("The PDF structure is damaged.");
            if (end > start && data.get(end - 1) == 10) end--;
            if (end > start && data.get(end - 1) == 13) end--;
        }
        byte[] out = new byte[end - start];
        ByteBuffer copy = data.duplicate();
        copy.position(start);
        copy.get(out);
        return out;
    }

    private int indexOf(String word, int from) {
        int n = word.length();
        for (int i = from; i <= size - n; i++) {
            if (data.get(i) != word.charAt(0)) continue;
            boolean match = true;
            for (int k = 1; k < n && match; k++) match = data.get(i + k) == word.charAt(k);
            if (match) return i;
        }
        return -1;
    }

    /** Decode a cross-reference stream: no filter, or Flate with an optional PNG predictor. */
    private byte[] decodeFlate(byte[] raw, Map<String, Object> dict) throws IOException {
        Object filter = dict.get("Filter");
        Object parms = dict.get("DecodeParms");
        if (filter instanceof List) {
            List<Object> list = asList(filter);
            if (list.size() > 1) throw new Unsupported("The PDF structure is not supported.");
            filter = list.isEmpty() ? null : list.get(0);
            List<Object> plist = asList(parms);
            parms = plist == null || plist.isEmpty() ? null : plist.get(0);
        }
        if (filter == null) return raw;
        String name = nameOf(filter);
        if (!"FlateDecode".equals(name) && !"Fl".equals(name)) throw new Unsupported("The PDF structure is not supported.");
        ByteArrayOutputStream out = new ByteArrayOutputStream(raw.length * 3);
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(raw);
            byte[] buffer = new byte[16384];
            while (!inflater.finished()) {
                int n = inflater.inflate(buffer);
                if (n == 0 && (inflater.needsInput() || inflater.needsDictionary())) break;
                out.write(buffer, 0, n);
            }
        } catch (DataFormatException e) {
            throw new Unsupported("The PDF structure is damaged.", e);
        } finally {
            inflater.end();
        }
        byte[] plain = out.toByteArray();
        int predictor = 1, columns = 1, colors = 1, bits = 8;
        if (parms instanceof Map) {
            Map<String, Object> pm = castMap(parms);
            if (pm.get("Predictor") != null) predictor = asInt(pm.get("Predictor"));
            if (pm.get("Columns") != null) columns = asInt(pm.get("Columns"));
            if (pm.get("Colors") != null) colors = asInt(pm.get("Colors"));
            if (pm.get("BitsPerComponent") != null) bits = asInt(pm.get("BitsPerComponent"));
        }
        if (predictor < 10) {
            if (predictor != 1) throw new Unsupported("The PDF structure is not supported.");
            return plain;
        }
        int bpp = Math.max(1, (colors * bits + 7) / 8);
        int rowBytes = (columns * colors * bits + 7) / 8;
        int rows = plain.length / (rowBytes + 1);
        byte[] result = new byte[rows * rowBytes];
        byte[] previous = new byte[rowBytes];
        byte[] current = new byte[rowBytes];
        for (int r = 0; r < rows; r++) {
            int at = r * (rowBytes + 1);
            int type = plain[at] & 0xFF;
            for (int i = 0; i < rowBytes; i++) {
                int x = plain[at + 1 + i] & 0xFF;
                int left = i >= bpp ? current[i - bpp] & 0xFF : 0;
                int up = previous[i] & 0xFF;
                int upLeft = i >= bpp ? previous[i - bpp] & 0xFF : 0;
                int value;
                switch (type) {
                    case 0: value = x; break;
                    case 1: value = x + left; break;
                    case 2: value = x + up; break;
                    case 3: value = x + ((left + up) >> 1); break;
                    case 4: {
                        int pa = Math.abs(up - upLeft), pb = Math.abs(left - upLeft), pc = Math.abs(left + up - 2 * upLeft);
                        value = x + (pa <= pb && pa <= pc ? left : pb <= pc ? up : upLeft);
                        break;
                    }
                    default: throw new Unsupported("The PDF structure is damaged.");
                }
                current[i] = (byte) value;
            }
            System.arraycopy(current, 0, result, r * rowBytes, rowBytes);
            byte[] swap = previous; previous = current; current = swap;
        }
        return result;
    }

    /** Parse the object stored at the offset the cross-reference table gives for {@code num}. */
    private Object readIndirect(int num) throws IOException {
        XEntry entry = xref.get(num);
        if (entry == null || entry.type != 1) throw new Unsupported("The PDF structure is damaged.");
        Parser p = at(entry.a);
        if (p.readLong() != num) throw new Unsupported("The PDF structure is damaged.");
        p.readLong();
        p.skipWhite();
        if (!p.readToken().equals("obj")) throw new Unsupported("The PDF structure is damaged.");
        return p.parseValue(0);
    }

    // ------------------------------------------------------------------------------------------
    // Encryption dictionary
    // ------------------------------------------------------------------------------------------

    private void readEncryption(Map<String, Object> enc) throws IOException {
        if (!"Standard".equals(nameOf(enc.get("Filter")))) {
            throw new Unsupported("This PDF uses a custom security handler that cannot be unlocked here.");
        }
        version = enc.get("V") instanceof Long ? asInt(enc.get("V")) : 0;
        revision = enc.get("R") instanceof Long ? asInt(enc.get("R")) : 0;
        ownerEntry = bytesOf(enc.get("O"));
        userEntry = bytesOf(enc.get("U"));
        if (enc.get("P") != null) permissions = (int) asLong(enc.get("P"));
        if (Boolean.FALSE.equals(enc.get("EncryptMetadata"))) encryptMetadata = false;
        Object idArray = trailer.get("ID");
        if (idArray instanceof List && !asList(idArray).isEmpty() && asList(idArray).get(0) instanceof Str) {
            id0 = ((Str) asList(idArray).get(0)).bytes;
        }
        int length = enc.get("Length") instanceof Long ? asInt(enc.get("Length")) : 40;
        switch (version) {
            case 1: keyLen = 5; break;
            case 2: case 3: keyLen = Math.max(5, Math.min(16, length / 8)); break;
            case 4: keyLen = 16; break;
            case 5: keyLen = 32; break;
            default: throw new Unsupported("This PDF's encryption version is not supported.");
        }
        if (revision < 2 || revision > 6) throw new Unsupported("This PDF's encryption revision is not supported.");
        if (revision == 2) keyLen = 5;
        if (version >= 4) {
            stmMethod = cryptMethod(enc, "StmF");
            strMethod = cryptMethod(enc, "StrF");
        } else {
            stmMethod = strMethod = Method.RC4;
        }
        if (revision >= 5) {
            ownerKeyEntry = bytesOf(enc.get("OE"));
            userKeyEntry = bytesOf(enc.get("UE"));
            if (ownerEntry.length < 48 || userEntry.length < 48 || ownerKeyEntry.length < 32 || userKeyEntry.length < 32) {
                throw new Unsupported("The PDF encryption settings are damaged.");
            }
        } else if (ownerEntry.length < 32 || userEntry.length < 32) {
            throw new Unsupported("The PDF encryption settings are damaged.");
        }
    }

    private static byte[] bytesOf(Object o) {
        return o instanceof Str ? ((Str) o).bytes : new byte[0];
    }

    private Method cryptMethod(Map<String, Object> enc, String which) throws Unsupported {
        String filterName = nameOf(enc.get(which));
        if (filterName == null || filterName.equals("Identity")) return Method.NONE;
        Object cf = enc.get("CF");
        Object entry = cf instanceof Map ? castMap(cf).get(filterName) : null;
        if (!(entry instanceof Map)) throw new Unsupported("The PDF encryption settings are damaged.");
        String cfm = nameOf(castMap(entry).get("CFM"));
        if ("None".equals(cfm)) return Method.NONE;
        if ("V2".equals(cfm)) return Method.RC4;
        if ("AESV2".equals(cfm)) return Method.AESV2;
        if ("AESV3".equals(cfm)) return Method.AESV3;
        throw new Unsupported("This PDF's encryption method is not supported.");
    }

    // ------------------------------------------------------------------------------------------
    // Rewriting
    // ------------------------------------------------------------------------------------------

    /**
     * Write an unprotected copy of the PDF to {@code out}. {@link #authenticate} must have succeeded.
     *
     * @throws Unsupported when the structure cannot be rewritten
     */
    void writeDecrypted(File out) throws IOException {
        if (fileKey == null) throw new IllegalStateException("authenticate() has not succeeded");
        try (CountingOutput os = new CountingOutput(new BufferedOutputStream(new FileOutputStream(out), 1 << 16))) {
            writeAll(os);
        } catch (Unsupported e) {
            out.delete();
            throw e;
        } catch (IOException | RuntimeException e) {
            out.delete();
            throw new Unsupported("The PDF could not be unlocked.", e);
        }
    }

    private void writeAll(CountingOutput os) throws IOException {
        os.write("%PDF-1.7\n%".getBytes(StandardCharsets.ISO_8859_1));
        os.write(new byte[]{(byte) 0xE2, (byte) 0xE3, (byte) 0xCF, (byte) 0xD3, 10});
        TreeMap<Integer, XEntry> written = new TreeMap<>();
        for (Map.Entry<Integer, XEntry> en : xref.entrySet()) {
            int num = en.getKey();
            XEntry entry = en.getValue();
            if (num == encObjNum || num < 0) continue;
            if (entry.type == 2) { written.put(num, entry); continue; }
            if (entry.type != 1) continue;
            Parser p = at(entry.a);
            if (p.readLong() != num) throw new Unsupported("The PDF structure is damaged.");
            int gen = (int) p.readLong();
            p.skipWhite();
            if (!p.readToken().equals("obj")) throw new Unsupported("The PDF structure is damaged.");
            Object value = p.parseValue(0);
            byte[] stream = null;
            Map<String, Object> dict = value instanceof Map ? castMap(value) : null;
            if (dict != null) {
                p.skipWhite();
                if (p.matches("stream")) {
                    p.pos += 6;
                    stream = readStreamBytes(p, dict);
                }
            }
            if (dict != null && ("XRef".equals(nameOf(dict.get("Type"))) || dict.containsKey("Linearized"))) continue;
            Object plainValue = decryptTree(value, num, gen);
            ByteArrayOutputStream head = new ByteArrayOutputStream();
            write(head, num + " " + gen + " obj\n");
            int plainLength = 0;
            if (stream != null) {
                Map<String, Object> plainDict = castMap(plainValue);
                plainLength = hasMethod(dict) ? decryptInPlace(stmMethod, stream, num, gen) : stream.length;
                plainDict.put("Length", Long.valueOf(plainLength));
                serialize(head, plainDict);
                write(head, "\nstream\n");
            } else {
                serialize(head, plainValue);
                write(head, "\nendobj\n");
            }
            written.put(num, new XEntry(1, os.count, gen));
            head.writeTo(os);
            if (stream != null) { // the (possibly huge) payload is written straight out, never copied again
                os.write(stream, 0, plainLength);
                write(os, "\nendstream\nendobj\n");
            }
        }
        if (written.isEmpty()) throw new Unsupported("The PDF has no readable objects.");
        long highest = written.lastKey();
        Object declaredSize = trailer.get("Size");
        int count = (int) Math.max(highest + 1, declaredSize instanceof Long ? (Long) declaredSize : 0);
        // The cross-reference stream is an object too, and lists itself.
        int xrefNum = count;
        long xrefOffset = os.count;
        written.put(xrefNum, new XEntry(1, xrefOffset, 0));
        ByteArrayOutputStream table = new ByteArrayOutputStream((count + 1) * 7);
        for (int i = 0; i <= count; i++) {
            XEntry e = written.get(i);
            int type = e == null ? 0 : e.type;
            long a = e == null ? 0 : e.a;
            int b = e == null ? (i == 0 ? 65535 : 0) : e.b;
            table.write(type);
            table.write((int) (a >>> 24) & 0xFF);
            table.write((int) (a >>> 16) & 0xFF);
            table.write((int) (a >>> 8) & 0xFF);
            table.write((int) a & 0xFF);
            table.write((b >>> 8) & 0xFF);
            table.write(b & 0xFF);
        }
        byte[] tableBytes = table.toByteArray();
        Map<String, Object> dict = new LinkedHashMap<>();
        dict.put("Type", new Name("XRef"));
        dict.put("Size", Long.valueOf(count + 1));
        dict.put("W", new ArrayList<Object>(Arrays.asList(Long.valueOf(1), Long.valueOf(4), Long.valueOf(2))));
        dict.put("Root", trailer.get("Root"));
        if (trailer.get("Info") instanceof Ref) dict.put("Info", trailer.get("Info"));
        if (trailer.get("ID") instanceof List) dict.put("ID", trailer.get("ID"));
        dict.put("Length", Long.valueOf(tableBytes.length));
        ByteArrayOutputStream tail = new ByteArrayOutputStream();
        write(tail, xrefNum + " 0 obj\n");
        serialize(tail, dict);
        write(tail, "\nstream\n");
        tail.write(tableBytes);
        write(tail, "\nendstream\nendobj\nstartxref\n" + xrefOffset + "\n%%EOF\n");
        tail.writeTo(os);
    }

    /** Streams marked with an identity crypt filter, and unencrypted metadata, are stored in the clear. */
    private boolean hasMethod(Map<String, Object> dict) {
        if (stmMethod == Method.NONE) return false;
        if (!encryptMetadata && "Metadata".equals(nameOf(dict.get("Type")))) return false;
        Object filter = dict.get("Filter");
        boolean crypt = "Crypt".equals(nameOf(filter));
        if (filter instanceof List && !asList(filter).isEmpty()) crypt = "Crypt".equals(nameOf(asList(filter).get(0)));
        if (crypt) {
            Object parms = dict.get("DecodeParms");
            if (parms instanceof List && !asList(parms).isEmpty()) parms = asList(parms).get(0);
            String name = parms instanceof Map ? nameOf(castMap(parms).get("Name")) : null;
            if (name == null || name.equals("Identity")) return false;
        }
        return true;
    }

    /** Copy of {@code value} with every string decrypted. */
    private Object decryptTree(Object value, int num, int gen) {
        if (value instanceof Str) {
            return strMethod == Method.NONE ? value : new Str(decryptBytes(strMethod, ((Str) value).bytes, num, gen));
        }
        if (value instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object item : asList(value)) out.add(decryptTree(item, num, gen));
            return out;
        }
        if (value instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : castMap(value).entrySet()) out.put(e.getKey(), decryptTree(e.getValue(), num, gen));
            return out;
        }
        return value;
    }

    private static void write(OutputStream out, String text) throws IOException {
        out.write(text.getBytes(StandardCharsets.ISO_8859_1));
    }

    private static void serialize(OutputStream out, Object value) throws IOException {
        if (value instanceof Long || value instanceof Boolean) {
            write(out, value.toString());
        } else if (value instanceof Real) {
            write(out, ((Real) value).text);
        } else if (value == NULL) {
            write(out, "null");
        } else if (value instanceof Name) {
            out.write('/');
            String name = ((Name) value).value;
            for (int i = 0; i < name.length(); i++) {
                int c = name.charAt(i) & 0xFF;
                if (c <= 32 || c >= 127 || c == '#' || isDelimiter(c)) {
                    write(out, String.format("#%02X", c));
                } else {
                    out.write(c);
                }
            }
        } else if (value instanceof Str) {
            out.write('<');
            for (byte b : ((Str) value).bytes) write(out, String.format("%02X", b & 0xFF));
            out.write('>');
        } else if (value instanceof Ref) {
            write(out, ((Ref) value).num + " " + ((Ref) value).gen + " R");
        } else if (value instanceof List) {
            out.write('[');
            boolean first = true;
            for (Object item : asList(value)) {
                if (!first) out.write(' ');
                first = false;
                serialize(out, item);
            }
            out.write(']');
        } else if (value instanceof Map) {
            write(out, "<<");
            for (Map.Entry<String, Object> e : castMap(value).entrySet()) {
                serialize(out, new Name(e.getKey()));
                out.write(' ');
                serialize(out, e.getValue());
                out.write(' ');
            }
            write(out, ">>");
        } else {
            throw new Unsupported("The PDF structure is damaged.");
        }
    }

    /** Output stream that counts the bytes written, to record object offsets. */
    private static final class CountingOutput extends OutputStream {
        private final OutputStream inner;
        long count;

        CountingOutput(OutputStream inner) { this.inner = inner; }

        @Override public void write(int b) throws IOException { inner.write(b); count++; }

        @Override public void write(byte[] b, int off, int len) throws IOException { inner.write(b, off, len); count += len; }

        @Override public void flush() throws IOException { inner.flush(); }

        @Override public void close() throws IOException { inner.close(); }
    }
}
