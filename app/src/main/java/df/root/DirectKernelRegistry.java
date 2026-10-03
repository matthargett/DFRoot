package df.root;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

final class DirectKernelRegistry {
    private static final String ASSET = "direct-kernel-targets.json";

    static final class Match {
        final DirectKernelTarget target;
        final File payload;

        Match(DirectKernelTarget target, File payload) {
            this.target = target;
            this.payload = payload;
        }
    }

    private DirectKernelRegistry() {}

    static Match findReady(Context context, IReporter reporter) {
        DirectKernelIdentity identity = DirectKernelIdentity.observe();
        identity.report(reporter);

        List<DirectKernelTarget> targets;
        try {
            targets = load(context);
        } catch (Exception error) {
            reporter.report("direct-kernel registry invalid: " + error + "\n");
            return null;
        }

        boolean identityMatched = false;
        for (DirectKernelTarget target : targets) {
            if (!identity.matches(target)) continue;
            identityMatched = true;
            reporter.report("direct-kernel exact firmware candidate: " + target.id + "\n");
            if (!PhysicalMemoryProbe.verify(target, reporter)) continue;
            File payload;
            try {
                File directory = new File(context.getApplicationInfo().nativeLibraryDir)
                        .getCanonicalFile();
                payload = new File(directory, target.provider.file).getCanonicalFile();
                if (!directory.equals(payload.getParentFile())) {
                    reporter.report("candidate " + target.id
                            + " rejected: provider escaped native library directory\n");
                    continue;
                }
            } catch (Exception error) {
                reporter.report("candidate " + target.id
                        + " rejected: provider path error=" + error + "\n");
                continue;
            }
            if (!payload.isFile()) {
                reporter.report("candidate " + target.id
                        + " unavailable: exact provider is not packaged file="
                        + target.provider.file + " expected_sha256="
                        + target.provider.sha256 + "\n");
                reporter.report("NEXT: obtain the provider under compatible terms, verify its hash, and package it as a native executable; never substitute a different build\n");
                continue;
            }
            String observed;
            try {
                observed = sha256(payload);
            } catch (Exception error) {
                reporter.report("candidate " + target.id
                        + " rejected: provider hash failed error=" + error + "\n");
                continue;
            }
            if (!target.provider.sha256.equals(observed)) {
                reporter.report("candidate " + target.id
                        + " rejected: provider SHA-256 mismatch observed="
                        + observed + " expected=" + target.provider.sha256 + "\n");
                continue;
            }
            if (!payload.canExecute()) {
                reporter.report("candidate " + target.id
                        + " rejected: exact provider is not executable path="
                        + payload + "\n");
                continue;
            }
            reporter.report("direct-kernel provider: path=" + payload
                    + " sha256=exact executable=yes\n");
            return new Match(target, payload);
        }
        if (!identityMatched) {
            reporter.report("direct-kernel strategy: no descriptor declares this exact device, fingerprint, patch level, incremental, and kernel release\n");
            reporter.report("NEXT: add a target only after a dry probe reports exact offsets and a live run proves a fresh UID 0 shell\n");
        }
        return null;
    }

    private static List<DirectKernelTarget> load(Context context) throws Exception {
        byte[] raw;
        try (InputStream input = context.getAssets().open(ASSET);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            for (int count; (count = input.read(buffer)) != -1; )
                output.write(buffer, 0, count);
            raw = output.toByteArray();
        }
        JSONObject root = new JSONObject(new String(raw, java.nio.charset.StandardCharsets.UTF_8));
        if (root.getInt("schema_version") != 1)
            throw new IllegalArgumentException("unsupported schema version");
        JSONArray array = root.getJSONArray("targets");
        List<DirectKernelTarget> targets = new ArrayList<>();
        for (int i = 0; i < array.length(); i++)
            targets.add(DirectKernelTarget.parse(array.getJSONObject(i)));
        return targets;
    }

    private static String sha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            for (int count; (count = input.read(buffer)) != -1; )
                digest.update(buffer, 0, count);
        }
        StringBuilder hex = new StringBuilder(64);
        for (byte value : digest.digest())
            hex.append(String.format(java.util.Locale.ROOT, "%02x", value & 0xff));
        return hex.toString();
    }
}
