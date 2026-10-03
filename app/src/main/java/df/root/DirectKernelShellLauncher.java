package df.root;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

final class DirectKernelShellLauncher {
    static final String FILE_NAME = "direct-kernel-shell-launcher.sh";
    static final String DEVICE_PATH = "/data/user_de/0/df.root/files/" + FILE_NAME;

    private DirectKernelShellLauncher() {}

    static void write(Context context, DirectKernelRegistry.Match match,
                      IReporter reporter) throws Exception {
        StringBuilder script = new StringBuilder();
        appendHeader(script, match);
        appendIdentityGuard(script, match.target);
        appendProviderGuard(script, match.target);
        appendPhysicalRangeGuard(script, match.target);
        appendDryProbe(script, match.target);
        appendProviderRun(script, match.target);

        File output = new File(context.createDeviceProtectedStorageContext().getFilesDir(),
                FILE_NAME);
        try (FileOutputStream stream = new FileOutputStream(output, false)) {
            stream.write(script.toString().getBytes(StandardCharsets.UTF_8));
            stream.flush();
        }
        reporter.report("direct-kernel shell launcher: path=" + output
                + " target=" + match.target.id + "\n");
        reporter.report("NEXT: adb shell 'run-as df.root cat " + DEVICE_PATH
                + " | sh'\n");
    }

    private static void appendHeader(StringBuilder script,
                                     DirectKernelRegistry.Match match) {
        line(script, "#!/system/bin/sh");
        line(script, "# Generated from an exact, hash-verified target descriptor.");
        line(script, "PATH=/system/bin:/system/xbin:/vendor/bin");
        line(script, "umask 077");
        assignment(script, "target", match.target.id);
        assignment(script, "payload", match.payload.getAbsolutePath());
    }

    private static void appendIdentityGuard(StringBuilder script,
                                            DirectKernelTarget target) {
        DirectKernelTarget.Identity identity = target.identity;
        assignment(script, "expected_incremental", identity.buildIncremental);
        assignment(script, "expected_fingerprint", identity.buildFingerprint);
        assignment(script, "expected_device", identity.device);
        assignment(script, "expected_security_patch", identity.securityPatch);
        assignment(script, "expected_kernel", identity.kernelRelease);
        line(script, "observed_incremental=\"$(getprop ro.build.version.incremental)\"");
        line(script, "observed_fingerprint=\"$(getprop ro.build.fingerprint)\"");
        line(script, "observed_device=\"$(getprop ro.product.device)\"");
        line(script, "observed_security_patch=\"$(getprop ro.build.version.security_patch)\"");
        line(script, "observed_kernel=\"$(uname -r)\"");
        line(script, "printf 'direct-kernel shell identity: target=%s device=%s incremental=%s patch=%s kernel=%s\\n' \"$target\" \"$observed_device\" \"$observed_incremental\" \"$observed_security_patch\" \"$observed_kernel\"");
        line(script, "if [ \"$observed_incremental\" != \"$expected_incremental\" ] || [ \"$observed_fingerprint\" != \"$expected_fingerprint\" ] || [ \"$observed_device\" != \"$expected_device\" ] || [ \"$observed_security_patch\" != \"$expected_security_patch\" ] || [ \"$observed_kernel\" != \"$expected_kernel\" ]; then");
        line(script, "  printf 'BLOCKED: exact build identity mismatch\\n' >&2");
        line(script, "  exit 20");
        line(script, "fi");
    }

    private static void appendProviderGuard(StringBuilder script,
                                            DirectKernelTarget target) {
        assignment(script, "expected_sha256", target.provider.sha256);
        line(script, "set -- $(sha256sum \"$payload\")");
        line(script, "observed_sha256=\"${1:-missing}\"");
        line(script, "if [ \"$observed_sha256\" != \"$expected_sha256\" ]; then");
        line(script, "  printf 'BLOCKED: provider SHA-256 mismatch observed=%s expected=%s\\n' \"$observed_sha256\" \"$expected_sha256\" >&2");
        line(script, "  exit 20");
        line(script, "fi");
    }

    private static void appendPhysicalRangeGuard(StringBuilder script,
                                                 DirectKernelTarget target) {
        DirectKernelTarget.PhysicalRange range = target.physicalRange;
        if (range == null) {
            line(script, "printf 'physical PFN envelope: target has no range guard\\n'");
            return;
        }
        line(script, "zone_range=\"$(awk '");
        line(script, "function finish_zone() {");
        line(script, "  if (start != \"\" && span + 0 > 0) {");
        line(script, "    zone_end = start + span");
        line(script, "    if (range_start == \"\" || start < range_start) range_start = start");
        line(script, "    if (range_end == \"\" || zone_end > range_end) range_end = zone_end");
        line(script, "  }");
        line(script, "}");
        line(script, "/^Node [0-9]+, zone/ { finish_zone(); start = \"\"; span = \"\"; next }");
        line(script, "$1 == \"spanned\" { span = $2; next }");
        line(script, "$1 == \"start_pfn:\" { start = $2; next }");
        line(script, "END { finish_zone(); print range_start, range_end }");
        line(script, "' /proc/zoneinfo)\"");
        line(script, "set -- $zone_range");
        line(script, "observed_pfn_start=\"${1:-missing}\"");
        line(script, "observed_pfn_end=\"${2:-missing}\"");
        line(script, "printf 'physical PFN envelope: shell_observed=[%s,%s) descriptor=[%s,%s)\\n' \"$observed_pfn_start\" \"$observed_pfn_end\" '"
                + range.observedStart + "' '" + range.observedUnalignedEnd + "'");
        line(script, "if [ \"$observed_pfn_start\" != '" + range.observedStart
                + "' ] || [ \"$observed_pfn_end\" != '"
                + range.observedUnalignedEnd + "' ]; then");
        line(script, "  printf 'BLOCKED: physical PFN range mismatch; re-derive rather than widening blindly\\n' >&2");
        line(script, "  exit 20");
        line(script, "fi");
    }

    private static void appendDryProbe(StringBuilder script,
                                       DirectKernelTarget target) {
        line(script, "dry_output=\"$(\"$payload\" --dry-offsets 2>&1)\"");
        line(script, "dry_status=$?");
        line(script, "printf '%s\\n' \"$dry_output\"");
        line(script, "if [ \"$dry_status\" -ne 0 ]; then");
        line(script, "  printf 'BLOCKED: provider dry probe exit=%s\\n' \"$dry_status\" >&2");
        line(script, "  exit 23");
        line(script, "fi");
        for (String marker : target.probe.successMarkers) {
            line(script, "printf '%s\\n' \"$dry_output\" | grep -Fq " + quote(marker));
            line(script, "if [ $? -ne 0 ]; then printf 'BLOCKED: provider dry marker missing: %s\\n' "
                    + quote(marker) + " >&2; exit 23; fi");
        }
    }

    private static void appendProviderRun(StringBuilder script,
                                          DirectKernelTarget target) {
        DirectKernelTarget.Run run = target.run;
        for (Map.Entry<String, String> entry : run.environment.entrySet())
            line(script, "export " + entry.getKey() + "=" + quote(entry.getValue()));
        assignment(script, "run_log", "/data/local/tmp/dfroot-direct-" + target.id + ".log");
        line(script, "attempt=1");
        line(script, "while [ \"$attempt\" -le '" + run.maximumAttempts + "' ]; do");
        line(script, "  printf 'direct-kernel shell attempt %s/%s; log=%s\\n' \"$attempt\" '"
                + run.maximumAttempts + "' \"$run_log\"");
        line(script, "  \"$payload\" 2>&1 | tee \"$run_log\"");
        line(script, "  provider_status=\"${PIPESTATUS[0]}\"");
        line(script, "  retryable=0");
        for (String marker : run.retryableMarkers) {
            line(script, "  grep -Fq " + quote(marker) + " \"$run_log\"");
            line(script, "  if [ $? -eq 0 ]; then retryable=1; fi");
        }
        line(script, "  printf 'direct-kernel shell exit=%s retryable_clean_failure=%s\\n' \"$provider_status\" \"$retryable\"");
        line(script, "  if [ \"$retryable\" -ne 1 ] || [ \"$attempt\" -ge '"
                + run.maximumAttempts + "' ]; then exit \"$provider_status\"; fi");
        line(script, "  attempt=$((attempt + 1))");
        line(script, "  printf 'retrying only after the exact guarded allocator-exhaustion marker\\n'");
        line(script, "  sleep '" + Math.max(1, (run.retryDelayMs + 999) / 1000) + "'");
        line(script, "done");
    }

    private static void assignment(StringBuilder output, String name, String value) {
        line(output, name + "=" + quote(value));
    }

    private static void line(StringBuilder output, String line) {
        output.append(line).append('\n');
    }

    private static String quote(String value) {
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }
}
