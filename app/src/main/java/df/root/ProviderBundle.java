package df.root;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class ProviderBundle {
    static final class Entry {
        final DirectKernelTarget.SupportFile support;
        final File privateFile;

        Entry(DirectKernelTarget.SupportFile support, File privateFile) {
            this.support = support;
            this.privateFile = privateFile;
        }
    }

    private ProviderBundle() {}

    static List<Entry> stage(Context context, DirectKernelTarget target,
                             IReporter reporter) throws Exception {
        if (target.supportFiles.isEmpty()) return Collections.emptyList();
        File files = context.createDeviceProtectedStorageContext().getFilesDir()
                .getCanonicalFile();
        File root = new File(files, "providers").getCanonicalFile();
        File directory = new File(root, target.id).getCanonicalFile();
        if (!root.equals(directory.getParentFile()))
            throw new IllegalArgumentException("provider directory escaped files root");
        if (!directory.isDirectory() && !directory.mkdirs())
            throw new IllegalStateException("could not create provider directory");

        List<Entry> staged = new ArrayList<>();
        for (DirectKernelTarget.SupportFile support : target.supportFiles) {
            File output = new File(directory, support.file).getCanonicalFile();
            if (!directory.equals(output.getParentFile()))
                throw new IllegalArgumentException("support file escaped provider directory");
            writeExactAsset(context, support, output);
            reporter.report("direct-kernel support: file=" + support.file
                    + " sha256=exact staged=yes\n");
            staged.add(new Entry(support, output));
        }
        return Collections.unmodifiableList(staged);
    }

    private static void writeExactAsset(Context context,
                                        DirectKernelTarget.SupportFile support,
                                        File output) throws Exception {
        if (output.isFile() && support.sha256.equals(Sha256.file(output))) {
            setMode(output, support.executable);
            return;
        }
        File temporary = new File(output.getPath() + ".tmp");
        try (InputStream input = context.getAssets().open(support.asset);
             FileOutputStream stream = new FileOutputStream(temporary, false)) {
            byte[] buffer = new byte[8192];
            for (int count; (count = input.read(buffer)) != -1; )
                stream.write(buffer, 0, count);
            stream.flush();
        } catch (Exception error) {
            temporary.delete();
            throw error;
        }
        String observed = Sha256.file(temporary);
        if (!support.sha256.equals(observed)) {
            temporary.delete();
            throw new IllegalStateException("support SHA-256 mismatch file="
                    + support.file + " observed=" + observed);
        }
        if (output.exists() && !output.delete()) {
            temporary.delete();
            throw new IllegalStateException("could not replace support file="
                    + support.file);
        }
        if (!temporary.renameTo(output)) {
            temporary.delete();
            throw new IllegalStateException("could not stage support file="
                    + support.file);
        }
        setMode(output, support.executable);
    }

    private static void setMode(File file, boolean executable) {
        if (!file.setReadable(true, true)
                || !file.setWritable(true, true)
                || !file.setExecutable(executable, true))
            throw new IllegalStateException("could not set support mode file="
                    + file.getName());
    }
}
