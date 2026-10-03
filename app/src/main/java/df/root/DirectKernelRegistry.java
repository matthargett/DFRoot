package df.root;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

final class DirectKernelRegistry {
    private static final String ASSET = "direct-kernel-targets.json";

    static final class Match {
        final DirectKernelTarget target;
        final File payload;
        final List<ProviderBundle.Entry> supportFiles;

        Match(DirectKernelTarget target, File payload,
              List<ProviderBundle.Entry> supportFiles) {
            this.target = target;
            this.payload = payload;
            this.supportFiles = supportFiles;
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
                observed = Sha256.file(payload);
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
            List<ProviderBundle.Entry> supportFiles;
            try {
                supportFiles = ProviderBundle.stage(context, target, reporter);
            } catch (Exception error) {
                reporter.report("candidate " + target.id
                        + " rejected: support staging failed error=" + error + "\n");
                continue;
            }
            return new Match(target, payload, supportFiles);
        }
        if (!identityMatched) {
            reporter.report("direct-kernel strategy: no descriptor matches this canonical build identity\n");
            reporter.report("NEXT: add a target only after a provider probe validates its exact inputs and a live run proves a fresh UID 0 shell\n");
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
        int version = root.getInt("schema_version");
        if (version != 1 && version != 2)
            throw new IllegalArgumentException("unsupported schema version");
        JSONArray array = root.getJSONArray("targets");
        List<DirectKernelTarget> targets = new ArrayList<>();
        for (int i = 0; i < array.length(); i++)
            targets.add(DirectKernelTarget.parse(array.getJSONObject(i)));
        return targets;
    }

}
