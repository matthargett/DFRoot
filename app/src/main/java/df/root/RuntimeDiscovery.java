package df.root;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class RuntimeDiscovery {
    private static final String ASSET = "runtime-discovery-policy.json";
    private static final int REPORT_LIMIT = 80;

    private RuntimeDiscovery() {}

    static void report(Context context, IReporter reporter) {
        try {
            Policy policy = Policy.load(context);
            Set<String> directories = policy.directories();
            List<String> candidates = new ArrayList<>();
            for (String directory : directories) {
                File root = new File(directory);
                if (!root.isDirectory()) continue;
                for (String name : policy.fileNames) {
                    File candidate = new File(root, name);
                    if (candidate.exists()) candidates.add(candidate.getAbsolutePath());
                }
                File[] files = root.listFiles();
                if (files == null) continue;
                for (File candidate : files) {
                    String name = candidate.getName();
                    if (candidate.isFile() && (name.endsWith(".ko")
                            || name.endsWith(".rc") || name.endsWith(".cfg")
                            || name.endsWith(".so") || name.contains(".so."))) {
                        candidates.add(candidate.getAbsolutePath());
                    }
                }
            }
            for (String path : policy.fixedEvidencePaths)
                if (new File(path).exists()) candidates.add(path);

            LinkedHashSet<String> unique = new LinkedHashSet<>(candidates);
            Map<String, List<String>> byClass = new LinkedHashMap<>();
            for (String path : unique)
                byClass.computeIfAbsent(classify(path), unused -> new ArrayList<>())
                        .add(path);
            reporter.report("runtime discovery: selection=filesystem_structure_and_content_policy "
                    + "visible_candidates=" + unique.size() + "\n");
            String[] classes = {
                "runtime_evidence", "kernel_module", "boot_config",
                "executable", "shared_library", "device_node"
            };
            int[] quotas = {16, 20, 20, 12, 12, 8};
            for (String type : classes)
                reporter.report("runtime candidate count: class=" + type
                        + " count=" + byClass.getOrDefault(type,
                        Collections.emptyList()).size() + "\n");
            int shown = 0;
            for (int index = 0; index < classes.length && shown < REPORT_LIMIT; index++) {
                String type = classes[index];
                List<String> paths = byClass.getOrDefault(type, Collections.emptyList());
                paths.sort(Comparator
                        .comparingInt((String path) -> policy.fileNames.contains(
                                new File(path).getName()) ? 0 : 1)
                        .thenComparing(path -> path));
                int count = Math.min(quotas[index], paths.size());
                for (int item = 0; item < count && shown < REPORT_LIMIT; item++, shown++)
                    reporter.report("runtime candidate: class=" + type
                            + " path=" + paths.get(item) + "\n");
            }
            reporter.report("runtime discovery next: run host structural probes for file metadata, "
                    + "ELF relocations, module vermagic, boot configuration grammar, and runtime symbol sources\n");
            reporter.report("runtime discovery guard: no build fingerprint or precomputed digest selected a candidate\n");
        } catch (Exception error) {
            reporter.report("runtime discovery failed: " + error + "\n");
        }
    }

    static String findCarrier(Context context, IReporter reporter) {
        try {
            Policy policy = Policy.load(context);
            for (String directory : policy.directories()) {
                if (!(directory.startsWith("/vendor")
                        || directory.startsWith("/odm")
                        || directory.startsWith("/product"))) continue;
                for (String name : policy.carrierFileNames) {
                    File candidate = new File(directory, name);
                    if (!candidate.isFile() || candidate.length() < 4096) continue;
                    reporter.report("runtime carrier candidate: path="
                            + candidate.getAbsolutePath() + " size=" + candidate.length()
                            + " selector=generic_name_and_structure\n");
                    return candidate.getAbsolutePath();
                }
            }
        } catch (Exception error) {
            reporter.report("runtime carrier discovery failed: " + error + "\n");
        }
        reporter.report("runtime carrier discovery: no policy candidate is present\n");
        return null;
    }

    private static String classify(String path) {
        String name = new File(path).getName();
        if (path.startsWith("/proc/") || path.startsWith("/sys/"))
            return "runtime_evidence";
        if (path.startsWith("/dev/")) return "device_node";
        if (name.endsWith(".ko")) return "kernel_module";
        if (name.endsWith(".rc") || name.endsWith(".cfg")
                || name.equals("modules.load") || name.equals("modules.dep"))
            return "boot_config";
        if (name.endsWith(".so") || name.contains(".so.")) return "shared_library";
        return "executable";
    }

    private static final class Policy {
        final List<String> prefixes;
        final List<String> suffixes;
        final List<String> fileNames;
        final List<String> carrierFileNames;
        final List<String> fixedEvidencePaths;

        Policy(List<String> prefixes, List<String> suffixes,
               List<String> fileNames, List<String> carrierFileNames,
               List<String> fixedEvidencePaths) {
            this.prefixes = prefixes;
            this.suffixes = suffixes;
            this.fileNames = fileNames;
            this.carrierFileNames = carrierFileNames;
            this.fixedEvidencePaths = fixedEvidencePaths;
        }

        Set<String> directories() {
            Set<String> values = new LinkedHashSet<>();
            for (String prefix : prefixes) {
                for (String suffix : suffixes) {
                    values.add(suffix.isEmpty() ? prefix : prefix + "/" + suffix);
                }
            }
            return values;
        }

        static Policy load(Context context) throws Exception {
            byte[] raw;
            try (InputStream input = context.getAssets().open(ASSET);
                 ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[8192];
                for (int count; (count = input.read(buffer)) != -1; )
                    output.write(buffer, 0, count);
                raw = output.toByteArray();
            }
            JSONObject root = new JSONObject(new String(raw, StandardCharsets.UTF_8));
            if (root.getInt("schema_version") != 1)
                throw new IllegalArgumentException("unsupported runtime discovery policy");
            return new Policy(
                    strings(root.getJSONArray("prefixes")),
                    strings(root.getJSONArray("suffixes")),
                    strings(root.getJSONArray("file_names")),
                    strings(root.getJSONArray("carrier_file_names")),
                    strings(root.getJSONArray("fixed_evidence_paths")));
        }

        static List<String> strings(JSONArray array) throws Exception {
            List<String> values = new ArrayList<>();
            for (int index = 0; index < array.length(); index++)
                values.add(array.getString(index));
            return values;
        }
    }
}
