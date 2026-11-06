package com.artcraft.photocraft;

import java.util.Locale;
import java.util.TreeSet;
import java.util.zip.CRC32;

/**
 * Android-free helpers behind PDF import (see {@link PdfImport}). They live in their own class so
 * they can be exercised on a desktop JVM without the Android framework.
 */
final class PdfPages {
    /** Most pages one import may turn into documents; each page opens as its own PhotoCraft document. */
    static final int MAX_PAGES_PER_IMPORT = 50;

    private PdfPages() {}

    /**
     * True when {@code head} holds a PDF header. The spec lets the {@code %PDF-} marker sit anywhere
     * in the first 1024 bytes (some producers prepend junk), so the whole prefix is searched.
     */
    static boolean isPdfHeader(byte[] head, int length) {
        int limit = Math.min(length, 1024) - 5;
        for (int i = 0; i <= limit; i++) {
            if (head[i] == '%' && head[i + 1] == 'P' && head[i + 2] == 'D' && head[i + 3] == 'F' && head[i + 4] == '-') {
                return true;
            }
        }
        return false;
    }

    /**
     * Parse a page selection such as {@code "1-3, 5"}, {@code "4-"} (page 4 to the end) or
     * {@code "all"} into sorted, distinct, zero-based page indexes.
     *
     * @throws IllegalArgumentException with a message fit to show the user
     */
    static int[] parseRange(String spec, int pageCount) {
        if (pageCount < 1) throw new IllegalArgumentException("This PDF has no pages.");
        String text = spec == null ? "" : spec.trim().toLowerCase(Locale.ROOT);
        if (text.isEmpty()) throw new IllegalArgumentException("Enter the pages to import, for example 1-3, 5 or all.");
        TreeSet<Integer> pages = new TreeSet<>();
        if (text.equals("all") || text.equals("*")) {
            for (int i = 0; i < pageCount; i++) pages.add(i);
        } else {
            for (String rawToken : text.split("[,;]")) {
                String token = rawToken.replace('\u2013', '-').replace('\u2014', '-').replaceAll("\\s+", "");
                if (token.isEmpty()) continue;
                int dash = token.indexOf('-');
                int from, to;
                try {
                    if (dash < 0) {
                        from = to = parsePage(token);
                    } else {
                        String left = token.substring(0, dash), right = token.substring(dash + 1);
                        if (left.isEmpty()) throw new NumberFormatException(token);
                        from = parsePage(left);
                        to = right.isEmpty() ? pageCount : parsePage(right);
                    }
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("\"" + rawToken.trim() + "\" is not a page number or range.");
                }
                if (from < 1 || from > pageCount) throw outside(from, pageCount);
                if (to < 1 || to > pageCount) throw outside(to, pageCount);
                if (to < from) throw new IllegalArgumentException("The range " + from + "-" + to + " runs backwards.");
                for (int p = from; p <= to; p++) {
                    pages.add(p - 1);
                    if (pages.size() > MAX_PAGES_PER_IMPORT) throw tooMany();
                }
            }
        }
        if (pages.isEmpty()) throw new IllegalArgumentException("Enter the pages to import, for example 1-3, 5 or all.");
        if (pages.size() > MAX_PAGES_PER_IMPORT) throw tooMany();
        int[] result = new int[pages.size()];
        int i = 0;
        for (int p : pages) result[i++] = p;
        return result;
    }

    private static int parsePage(String digits) {
        // Reject signs, hex and whitespace that Integer.parseInt would partly tolerate; cap the length
        // so a long run of digits cannot overflow into a "valid" page.
        if (digits.isEmpty() || digits.length() > 6) throw new NumberFormatException(digits);
        for (int i = 0; i < digits.length(); i++) {
            if (digits.charAt(i) < '0' || digits.charAt(i) > '9') throw new NumberFormatException(digits);
        }
        return Integer.parseInt(digits);
    }

    private static IllegalArgumentException outside(int page, int pageCount) {
        return new IllegalArgumentException("Page " + page + " is outside this PDF (1-" + pageCount + ").");
    }

    private static IllegalArgumentException tooMany() {
        return new IllegalArgumentException("Choose at most " + MAX_PAGES_PER_IMPORT + " pages at a time.");
    }

    /** File name for one imported page: {@code doc.png} for a one-page import, else {@code doc - p3.png}. */
    static String pageFileName(String stem, int pageNumber, int pagesImported) {
        String base = stem == null || stem.trim().isEmpty() ? "pdf-import" : stem.trim();
        return pagesImported == 1 ? base + ".png" : base + " - p" + pageNumber + ".png";
    }

    /**
     * Return {@code png} with a {@code pHYs} chunk declaring {@code dpi}, so PhotoCraft opens the page
     * at its real printed size rather than assuming 72 ppi. Android's PNG encoder writes no
     * resolution. A file that is not a PNG, or already carries a {@code pHYs}, comes back unchanged.
     */
    static byte[] withDpi(byte[] png, int dpi) {
        final int ihdrEnd = 8 + 4 + 4 + 13 + 4; // signature + length + "IHDR" + data + CRC
        if (png == null || png.length < ihdrEnd + 12 || dpi < 1) return png;
        final byte[] signature = {(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
        for (int i = 0; i < signature.length; i++) if (png[i] != signature[i]) return png;
        if (png[12] != 'I' || png[13] != 'H' || png[14] != 'D' || png[15] != 'R') return png;
        // Walk the chunks only far enough to know whether a pHYs is already there (it must precede IDAT).
        int pos = ihdrEnd;
        while (pos + 8 <= png.length) {
            long length = readInt(png, pos) & 0xFFFFFFFFL;
            boolean isPhys = png[pos + 4] == 'p' && png[pos + 5] == 'H' && png[pos + 6] == 'Y' && png[pos + 7] == 's';
            boolean isIdat = png[pos + 4] == 'I' && png[pos + 5] == 'D' && png[pos + 6] == 'A' && png[pos + 7] == 'T';
            if (isPhys) return png;
            if (isIdat) break;
            long next = pos + 12L + length;
            if (next > png.length) break;
            pos = (int) next;
        }
        long perMetre = Math.round(dpi / 0.0254);
        byte[] chunk = new byte[4 + 4 + 9 + 4];
        writeInt(chunk, 0, 9);
        chunk[4] = 'p'; chunk[5] = 'H'; chunk[6] = 'Y'; chunk[7] = 's';
        writeInt(chunk, 8, (int) perMetre);
        writeInt(chunk, 12, (int) perMetre);
        chunk[16] = 1; // unit: metre
        CRC32 crc = new CRC32();
        crc.update(chunk, 4, 4 + 9);
        writeInt(chunk, 17, (int) crc.getValue());
        byte[] out = new byte[png.length + chunk.length];
        System.arraycopy(png, 0, out, 0, ihdrEnd);
        System.arraycopy(chunk, 0, out, ihdrEnd, chunk.length);
        System.arraycopy(png, ihdrEnd, out, ihdrEnd + chunk.length, png.length - ihdrEnd);
        return out;
    }

    private static int readInt(byte[] b, int at) {
        return ((b[at] & 0xFF) << 24) | ((b[at + 1] & 0xFF) << 16) | ((b[at + 2] & 0xFF) << 8) | (b[at + 3] & 0xFF);
    }

    private static void writeInt(byte[] b, int at, int value) {
        b[at] = (byte) (value >>> 24);
        b[at + 1] = (byte) (value >>> 16);
        b[at + 2] = (byte) (value >>> 8);
        b[at + 3] = (byte) value;
    }
}
