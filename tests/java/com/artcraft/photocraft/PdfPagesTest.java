// Desktop-JVM test for adapters/photocraft/java/com/artcraft/photocraft/PdfPages.java (the
// Android-free half of PDF import). From the repository root:
//
//   javac -d /tmp/pdfpages-test adapters/photocraft/java/com/artcraft/photocraft/PdfPages.java \
//         tests/java/com/artcraft/photocraft/PdfPagesTest.java
//   java -cp /tmp/pdfpages-test com.artcraft.photocraft.PdfPagesTest
//
// Prints PASS/FAIL per check and exits non-zero on any failure.
package com.artcraft.photocraft;

import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.file.*;
import java.util.Arrays;
import javax.imageio.ImageIO;

public class PdfPagesTest {
    static int failures = 0;
    static void check(String name, boolean ok) { System.out.println((ok ? "PASS " : "FAIL ") + name); if (!ok) failures++; }
    static void ranges(String spec, int n, int[] expect) {
        try { int[] got = PdfPages.parseRange(spec, n); check("range '" + spec + "'/" + n + " -> " + Arrays.toString(expect), Arrays.equals(got, expect)); }
        catch (Exception e) { check("range '" + spec + "' unexpected " + e.getMessage(), false); }
    }
    static void rangeErr(String spec, int n, String contains) {
        try { PdfPages.parseRange(spec, n); check("range '" + spec + "' should fail", false); }
        catch (IllegalArgumentException e) { check("range '" + spec + "' rejected: " + e.getMessage(), e.getMessage().contains(contains)); }
    }
    public static void main(String[] a) throws Exception {
        ranges("1", 10, new int[]{0});
        ranges("1-3, 5", 10, new int[]{0,1,2,4});
        ranges(" 3 - 4 ;  9 ", 10, new int[]{2,3,8});
        ranges("ALL", 4, new int[]{0,1,2,3});
        ranges("*", 2, new int[]{0,1});
        ranges("4-", 6, new int[]{3,4,5});
        ranges("2\u20134", 6, new int[]{1,2,3});          // en dash
        ranges("5,1,5,2-3", 6, new int[]{0,1,2,4});        // dedupe + sort
        ranges("1,,2", 3, new int[]{0,1});                  // empty token ignored
        rangeErr("", 3, "Enter the pages");
        rangeErr("  ", 3, "Enter the pages");
        rangeErr(",", 3, "Enter the pages");
        rangeErr("0", 3, "outside");
        rangeErr("4", 3, "outside");
        rangeErr("1-9", 3, "outside");
        rangeErr("5-3", 9, "backwards");
        rangeErr("a", 3, "not a page");
        rangeErr("-2", 3, "not a page");
        rangeErr("+2", 3, "not a page");
        rangeErr("1.5", 3, "not a page");
        rangeErr("99999999999999999999", 3, "not a page");
        rangeErr("1-100", 500, "at most 50");
        rangeErr("all", 51, "at most 50");
        ranges("all", 50, java.util.stream.IntStream.range(0,50).toArray());
        rangeErr("1", 0, "no pages");

        check("pageFileName single", PdfPages.pageFileName("Report", 1, 1).equals("Report.png"));
        check("pageFileName multi", PdfPages.pageFileName("Report", 7, 3).equals("Report - p7.png"));
        check("pageFileName blank stem", PdfPages.pageFileName("  ", 1, 1).equals("pdf-import.png"));

        byte[] pdf = "%PDF-1.7\n1 0 obj".getBytes("ISO-8859-1");
        check("isPdfHeader plain", PdfPages.isPdfHeader(pdf, pdf.length));
        byte[] junk = new byte[600]; byte[] mk = "%PDF-1.4".getBytes(); System.arraycopy(mk, 0, junk, 500, mk.length);
        check("isPdfHeader after junk", PdfPages.isPdfHeader(junk, junk.length));
        byte[] late = new byte[1200]; System.arraycopy(mk, 0, late, 1100, mk.length);
        check("isPdfHeader beyond 1024 rejected", !PdfPages.isPdfHeader(late, late.length));
        byte[] png0 = {(byte)0x89,'P','N','G'};
        check("isPdfHeader png rejected", !PdfPages.isPdfHeader(png0, png0.length));
        check("isPdfHeader empty", !PdfPages.isPdfHeader(new byte[0], 0));
        byte[] cut = "%PDF".getBytes();
        check("isPdfHeader truncated marker", !PdfPages.isPdfHeader(cut, cut.length));

        // PNG dpi splice
        BufferedImage img = new BufferedImage(40, 30, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < 30; y++) for (int x = 0; x < 40; x++) img.setRGB(x, y, (x * 6) << 16 | (y * 8) << 8 | 0x40);
        ByteArrayOutputStream bos = new ByteArrayOutputStream(); ImageIO.write(img, "png", bos);
        byte[] png = bos.toByteArray();
        byte[] out = PdfPages.withDpi(png, 150);
        check("withDpi grows by 21 bytes", out.length == png.length + 21);
        BufferedImage back = ImageIO.read(new ByteArrayInputStream(out));
        boolean same = back.getWidth() == 40 && back.getHeight() == 30;
        for (int y = 0; y < 30 && same; y++) for (int x = 0; x < 40; x++) if ((back.getRGB(x, y) & 0xFFFFFF) != (img.getRGB(x, y) & 0xFFFFFF)) { same = false; break; }
        check("pixels survive splice", same);
        byte[] again = PdfPages.withDpi(out, 300);
        check("idempotent when pHYs present", Arrays.equals(again, out));
        check("non-PNG unchanged", Arrays.equals(PdfPages.withDpi(pdf, 150), pdf));
        check("null safe", PdfPages.withDpi(null, 150) == null);
        System.out.println(failures == 0 ? "ALL PASSED" : failures + " FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
