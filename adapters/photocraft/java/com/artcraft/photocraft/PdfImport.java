package com.artcraft.photocraft;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.pdf.PdfRenderer;
import android.os.ParcelFileDescriptor;
import android.text.InputType;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * PDF import for PhotoCraft on Android.
 *
 * <p>Upstream PhotoCraft cannot open a PDF (its own notes list PDF import as open work), and the
 * builder never edits upstream sources. Android already ships a PDF rasteriser, {@link PdfRenderer},
 * so the activity rasterises the pages the user picks into PNG files in app storage and hands those
 * to the Rust shell exactly like any other picked image. No native dependency is added.
 *
 * <p>Everything here runs on the activity's single I/O thread except {@link #prompt}'s dialog, which
 * is shown on the UI thread while the I/O thread waits for the answer.
 */
final class PdfImport {
    private static final String TAG = "PhotoCraftPdf";

    /** Longest edge and total pixel budget of one rendered page, to keep a poster-sized page from exhausting memory. */
    private static final int MAX_EDGE_PX = 8192;
    private static final long MAX_PIXELS = 36_000_000L;

    static final int DPI_SCREEN = 96;
    static final int DPI_STANDARD = 150;
    static final int DPI_PRINT = 300;

    private PdfImport() {}

    /** What the user chose in the import dialog. */
    static final class Options {
        final int[] pages; // zero-based, ascending
        final int dpi;

        Options(int[] pages, int dpi) {
            this.pages = pages;
            this.dpi = dpi;
        }
    }

    /** A problem whose message is fit to show the user as is. */
    static class Failure extends Exception {
        private static final long serialVersionUID = 1L;

        Failure(String message) { super(message); }

        Failure(String message, Throwable cause) { super(message, cause); }
    }

    /** The PDF needs a password before any page can be read; see {@link #unlock}. */
    static final class PasswordRequired extends Failure {
        private static final long serialVersionUID = 1L;

        PasswordRequired(Throwable cause) {
            super("This PDF is password-protected.", cause);
        }
    }

    /** Tells the password dialog whether what the user typed opens the PDF. */
    interface PasswordCheck {
        boolean accepts(String password);
    }

    /** Supplies the file a rendered page is written to (the activity picks a free name in its staging folder). */
    interface Targets {
        File create(String fileName) throws Exception;
    }

    /** True when the file starts like a PDF. The content decides, not the extension. */
    static boolean isPdf(File file) {
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] head = new byte[1024];
            int length = readFully(in, head);
            return PdfPages.isPdfHeader(head, length);
        } catch (IOException e) {
            return false;
        }
    }

    static int readFully(java.io.InputStream in, byte[] buffer) throws IOException {
        int total = 0;
        while (total < buffer.length) {
            int n = in.read(buffer, total, buffer.length - total);
            if (n < 0) break;
            total += n;
        }
        return total;
    }

    static int pageCount(File pdf) throws Failure {
        try (ParcelFileDescriptor fd = ParcelFileDescriptor.open(pdf, ParcelFileDescriptor.MODE_READ_ONLY);
             PdfRenderer renderer = new PdfRenderer(fd)) {
            int count = renderer.getPageCount();
            if (count < 1) throw new Failure("This PDF has no pages.");
            return count;
        } catch (SecurityException e) {
            throw new PasswordRequired(e);
        } catch (IOException | RuntimeException e) {
            throw new Failure("Could not read this PDF. The file may be damaged.", e);
        }
    }

    /**
     * Ask for the password of a protected PDF and write an unprotected copy into {@code outDir}.
     * {@link PdfRenderer} accepts a password only on the newest Android versions, so the copy is made
     * by {@link PdfDecrypt}; either the user or the owner password works. The original file is never
     * changed. The caller must delete the returned copy as soon as it has rendered what it needs.
     *
     * <p>Blocks the calling thread (never the UI thread) while the dialog is open. A wrong password
     * is reported inside the dialog, which stays open for another try.
     *
     * @return the unprotected copy, or {@code null} when the user cancelled
     */
    static File unlock(Activity activity, File pdf, File outDir, String documentName) throws Failure {
        try (PdfDecrypt decrypt = PdfDecrypt.open(pdf)) {
            String password = "";
            // A file that only has an owner password opens with an empty one; no need to ask.
            if (!decrypt.authenticate(password)) {
                password = promptPassword(activity, documentName, decrypt::authenticate);
                if (password == null) return null;
                if (!decrypt.authenticate(password)) throw new Failure("The password was not accepted.");
            }
            File unlocked = File.createTempFile("unlocked-", ".pdf", outDir);
            try {
                decrypt.writeDecrypted(unlocked);
                return unlocked;
            } catch (IOException | RuntimeException e) {
                unlocked.delete();
                throw e;
            }
        } catch (PdfDecrypt.Unsupported e) {
            Log.w(TAG, "Cannot unlock the PDF: " + e.getMessage(), e);
            throw new Failure("This PDF's protection is not supported, so it cannot be unlocked here.", e);
        } catch (IOException | RuntimeException e) {
            throw new Failure("Could not unlock this PDF.", e);
        }
    }

    /**
     * Show the password dialog and wait for the answer. The password is checked inside the dialog
     * ({@code check} runs on the UI thread and is quick), so a wrong one never closes it.
     *
     * @return the accepted password, or {@code null} when the user cancelled or the dialog could not be shown
     */
    private static String promptPassword(final Activity activity, final String documentName, final PasswordCheck check) {
        final Object cancelled = new Object();
        final BlockingQueue<Object> answer = new ArrayBlockingQueue<>(1);
        activity.runOnUiThread(() -> {
            try {
                showPasswordDialog(activity, documentName, check, answer, cancelled);
            } catch (Throwable error) {
                Log.e(TAG, "Could not show the PDF password dialog", error);
                answer.offer(cancelled);
            }
        });
        try {
            Object result = answer.poll(15, TimeUnit.MINUTES);
            return result instanceof String ? (String) result : null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    private static void showPasswordDialog(Activity activity, String documentName, final PasswordCheck check,
                                           final BlockingQueue<Object> answer, final Object cancelled) {
        final AlertDialog.Builder builder = new AlertDialog.Builder(activity);
        final Context context = builder.getContext();
        final float density = context.getResources().getDisplayMetrics().density;
        final int pad = (int) (20 * density);
        final int gap = (int) (12 * density);

        LinearLayout root = new LinearLayout(context);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, gap, pad, 0);

        TextView message = new TextView(context);
        message.setText(documentName == null || documentName.isEmpty()
                ? "This PDF is password-protected. Enter the password to import it."
                : documentName + " is password-protected. Enter the password to import it.");
        root.addView(message);

        final EditText input = new EditText(context);
        input.setSingleLine(true);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        input.setHint("Password");
        root.addView(input);

        CheckBox show = new CheckBox(context);
        show.setText("Show password");
        show.setOnCheckedChangeListener((button, checked) -> {
            input.setTransformationMethod(checked ? HideReturnsTransformationMethod.getInstance() : PasswordTransformationMethod.getInstance());
            input.setSelection(input.getText().length());
        });
        root.addView(show);

        builder.setTitle("Password required")
                .setView(root)
                .setPositiveButton("Unlock", null) // wired below so a wrong password keeps the dialog open
                .setNegativeButton("Cancel", null)
                .setCancelable(true);
        final AlertDialog dialog = builder.create();
        dialog.setCanceledOnTouchOutside(false);
        dialog.setOnDismissListener(d -> answer.offer(cancelled)); // the first answer wins
        if (dialog.getWindow() != null) {
            dialog.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE);
        }
        dialog.show();
        input.requestFocus();
        final View.OnClickListener submit = v -> {
            String typed = input.getText().toString();
            if (typed.isEmpty()) {
                input.setError("Enter the password");
                return;
            }
            if (check.accepts(typed)) {
                answer.offer(typed);
                dialog.dismiss();
            } else {
                input.setError("Incorrect password. Try again.");
                input.selectAll();
            }
        };
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(submit);
        input.setOnEditorActionListener((view, actionId, event) -> {
            submit.onClick(view);
            return true;
        });
    }

    /**
     * Ask which pages to import and at what resolution. Blocks the calling thread (never call it on
     * the UI thread) until the user answers.
     *
     * @return the choice, or {@code null} when the user cancelled or the dialog could not be shown
     */
    static Options prompt(final Activity activity, final String documentName, final int pageCount, final int defaultDpi) {
        final Object cancelled = new Object();
        final BlockingQueue<Object> answer = new ArrayBlockingQueue<>(1);
        activity.runOnUiThread(() -> {
            try {
                show(activity, documentName, pageCount, defaultDpi, answer, cancelled);
            } catch (Throwable error) {
                Log.e(TAG, "Could not show the PDF import dialog", error);
                answer.offer(cancelled);
            }
        });
        try {
            Object result = answer.poll(15, TimeUnit.MINUTES);
            return result instanceof Options ? (Options) result : null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    private static void show(final Activity activity, String documentName, final int pageCount, int defaultDpi,
                             final BlockingQueue<Object> answer, final Object cancelled) {
        final AlertDialog.Builder builder = new AlertDialog.Builder(activity);
        // Build the views in the dialog's own themed context so text and background always agree.
        final Context context = builder.getContext();
        final float density = context.getResources().getDisplayMetrics().density;
        final int pad = (int) (20 * density);
        final int gap = (int) (12 * density);

        LinearLayout root = new LinearLayout(context);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, gap, pad, 0);

        TextView summary = new TextView(context);
        summary.setText(pageCount == 1 ? "1 page" : pageCount + " pages");
        root.addView(summary);

        final EditText pages = new EditText(context);
        if (pageCount > 1) {
            TextView label = new TextView(context);
            label.setText("Pages to import (each opens as its own document)");
            label.setPadding(0, gap, 0, 0);
            root.addView(label);
            pages.setSingleLine(true);
            pages.setInputType(InputType.TYPE_CLASS_TEXT);
            pages.setHint("e.g. 1-3, 5 or all");
            pages.setText("1");
            pages.setSelectAllOnFocus(true);
            root.addView(pages);
        }

        TextView resolution = new TextView(context);
        resolution.setText("Resolution");
        resolution.setPadding(0, gap, 0, 0);
        root.addView(resolution);

        final RadioGroup group = new RadioGroup(context);
        group.setOrientation(RadioGroup.VERTICAL);
        final int[] dpis = {DPI_SCREEN, DPI_STANDARD, DPI_PRINT};
        final String[] labels = {"96 ppi \u2013 screen", "150 ppi \u2013 standard", "300 ppi \u2013 print (large)"};
        final int[] ids = new int[dpis.length];
        int selected = 1;
        for (int i = 0; i < dpis.length; i++) {
            RadioButton button = new RadioButton(context);
            button.setText(labels[i]);
            button.setId(View.generateViewId());
            ids[i] = button.getId();
            group.addView(button);
            if (dpis[i] == defaultDpi) selected = i;
        }
        group.check(ids[selected]);
        root.addView(group);

        builder.setTitle(documentName == null || documentName.isEmpty() ? "Import PDF" : "Import " + documentName)
                .setView(root)
                .setPositiveButton("Import", null) // wired below so a bad page list keeps the dialog open
                .setNegativeButton("Cancel", null)
                .setCancelable(true);
        final AlertDialog dialog = builder.create();
        dialog.setCanceledOnTouchOutside(false);
        // Whatever closes the dialog, the waiting I/O thread gets an answer; the first answer wins.
        dialog.setOnDismissListener(d -> answer.offer(cancelled));
        dialog.show();
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            int[] chosen;
            try {
                chosen = pageCount > 1 ? PdfPages.parseRange(pages.getText().toString(), pageCount) : new int[]{0};
            } catch (IllegalArgumentException e) {
                pages.setError(e.getMessage());
                pages.requestFocus();
                return;
            }
            int dpi = DPI_STANDARD;
            for (int i = 0; i < ids.length; i++) if (group.getCheckedRadioButtonId() == ids[i]) dpi = dpis[i];
            answer.offer(new Options(chosen, dpi));
            dialog.dismiss();
        });
    }

    /**
     * Rasterise the chosen pages to PNG files on a white background, writing the real resolution into
     * each file. A page too large for the pixel budget is rendered smaller, and its recorded resolution
     * is lowered to match so it still opens at its true physical size.
     *
     * @param stem    the document name without extension, used to name the pages
     * @return the written files, in page order
     */
    static List<File> render(File pdf, int[] pageIndexes, int dpi, String stem, Targets targets) throws Failure {
        List<File> written = new ArrayList<>();
        try (ParcelFileDescriptor fd = ParcelFileDescriptor.open(pdf, ParcelFileDescriptor.MODE_READ_ONLY);
             PdfRenderer renderer = new PdfRenderer(fd)) {
            for (int index : pageIndexes) {
                if (index < 0 || index >= renderer.getPageCount()) continue;
                written.add(renderPage(renderer, index, dpi, stem, pageIndexes.length, targets));
            }
        } catch (Failure e) {
            deleteAll(written);
            throw e;
        } catch (SecurityException e) {
            deleteAll(written);
            throw new Failure("This PDF is password-protected. Remove the password, then import it again.", e);
        } catch (Exception e) {
            deleteAll(written);
            throw new Failure("Could not read this PDF. The file may be damaged.", e);
        }
        return written;
    }

    private static File renderPage(PdfRenderer renderer, int index, int dpi, String stem, int pagesImported,
                                   Targets targets) throws Exception {
        Bitmap bitmap = null;
        try (PdfRenderer.Page page = renderer.openPage(index)) {
            // PDF page sizes are in points (1/72 inch).
            final double widthPt = Math.max(1, page.getWidth());
            final double heightPt = Math.max(1, page.getHeight());
            double scale = dpi / 72.0;
            scale = Math.min(scale, MAX_EDGE_PX / Math.max(widthPt, heightPt));
            scale = Math.min(scale, Math.sqrt((double) MAX_PIXELS / (widthPt * heightPt)));
            final int width = Math.max(1, (int) Math.round(widthPt * scale));
            final int height = Math.max(1, (int) Math.round(heightPt * scale));
            final int effectiveDpi = Math.max(1, (int) Math.round(scale * 72.0));

            try {
                bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
            } catch (OutOfMemoryError oom) {
                throw new Failure("Not enough memory to import page " + (index + 1) + " at " + dpi
                        + " ppi. Try a lower resolution.", oom);
            }
            // Pages without a background render onto transparency; paper is white.
            bitmap.eraseColor(Color.WHITE);
            page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY);

            ByteArrayOutputStream encoded = new ByteArrayOutputStream(Math.max(64 * 1024, width * height / 4));
            if (!bitmap.compress(Bitmap.CompressFormat.PNG, 100, encoded)) {
                throw new Failure("Could not encode page " + (index + 1) + " as an image.");
            }
            byte[] png = PdfPages.withDpi(encoded.toByteArray(), effectiveDpi);

            File target = targets.create(PdfPages.pageFileName(stem, index + 1, pagesImported));
            File partial = new File(target.getParentFile(), target.getName() + ".part");
            try (FileOutputStream out = new FileOutputStream(partial)) {
                out.write(png);
                out.flush();
            }
            if (target.exists() && !target.delete()) {
                partial.delete();
                throw new IOException("Could not replace the earlier import " + target.getName());
            }
            if (!partial.renameTo(target)) {
                partial.delete();
                throw new IOException("Could not save page " + (index + 1));
            }
            Log.i(TAG, "Imported PDF page " + (index + 1) + " as " + width + "x" + height + " px at " + effectiveDpi + " ppi");
            return target;
        } finally {
            if (bitmap != null) bitmap.recycle();
        }
    }

    private static void deleteAll(List<File> files) {
        for (File file : files) {
            if (!file.delete()) Log.w(TAG, "Could not remove a partial import: " + file.getName());
        }
        files.clear();
    }
}
