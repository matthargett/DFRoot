package df.root;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
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
        appendProviderStage(script, match);
        appendSupportStage(script, match);
        appendPhysicalRangeGuard(script, match.target);
        appendProviderProbe(script, match.target);
        appendStageOnlyGuard(script);
        appendProviderRun(script, match.target);

        File output = new File(context.createDeviceProtectedStorageContext().getFilesDir(),
                FILE_NAME);
        try (FileOutputStream stream = new FileOutputStream(output, false)) {
            stream.write(script.toString().getBytes(StandardCharsets.UTF_8));
            stream.flush();
        }
        reporter.report("direct-kernel shell launcher: path=" + output
                + " target=" + match.target.id + "\n");
        reporter.report("VERIFY: adb shell 'run-as df.root cat " + DEVICE_PATH
                + " | DFROOT_STAGE_ONLY=1 sh'\n");
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
        assignment(script, "private_payload", match.payload.getAbsolutePath());
        line(script, "bundle=\"/data/local/tmp/dfroot-provider-${target}-$$\"");
        line(script, "if ! mkdir -m 700 \"$bundle\"; then");
        line(script, "  printf 'BLOCKED: could not create private provider directory\\n' >&2");
        line(script, "  exit 20");
        line(script, "fi");
        line(script, "trap 'rm -rf \"$bundle\"' 0 1 2 15");
    }

    private static void appendIdentityGuard(StringBuilder script,
                                            DirectKernelTarget target) {
        DirectKernelTarget.Identity identity = target.identity;
        line(script, "observed_incremental=\"$(getprop ro.build.version.incremental)\"");
        line(script, "observed_fingerprint=\"$(getprop ro.build.fingerprint)\"");
        line(script, "observed_security_patch=\"$(getprop ro.build.version.security_patch)\"");
        line(script, "observed_kernel=\"$(uname -r)\"");
        if (identity.sha256 != null) {
            assignment(script, "expected_identity_sha256", identity.sha256);
            line(script, "set -- $(printf '%s\\n%s\\n%s\\n%s\\n' \"$observed_fingerprint\" \"$observed_incremental\" \"$observed_security_patch\" \"$observed_kernel\" | sha256sum)");
            line(script, "observed_identity_sha256=\"${1:-missing}\"");
            line(script, "printf 'direct-kernel shell identity: target=%s sha256=%s incremental=%s patch=%s kernel=%s\\n' \"$target\" \"$observed_identity_sha256\" \"$observed_incremental\" \"$observed_security_patch\" \"$observed_kernel\"");
            line(script, "if [ \"$observed_identity_sha256\" != \"$expected_identity_sha256\" ]; then");
        } else {
            assignment(script, "expected_incremental", identity.buildIncremental);
            assignment(script, "expected_fingerprint", identity.buildFingerprint);
            assignment(script, "expected_device", identity.device);
            assignment(script, "expected_security_patch", identity.securityPatch);
            assignment(script, "expected_kernel", identity.kernelRelease);
            line(script, "observed_device=\"$(getprop ro.product.device)\"");
            line(script, "printf 'direct-kernel shell identity: target=%s incremental=%s patch=%s kernel=%s\\n' \"$target\" \"$observed_incremental\" \"$observed_security_patch\" \"$observed_kernel\"");
            line(script, "if [ \"$observed_incremental\" != \"$expected_incremental\" ] || [ \"$observed_fingerprint\" != \"$expected_fingerprint\" ] || [ \"$observed_device\" != \"$expected_device\" ] || [ \"$observed_security_patch\" != \"$expected_security_patch\" ] || [ \"$observed_kernel\" != \"$expected_kernel\" ]; then");
        }
        line(script, "  printf 'BLOCKED: exact build identity mismatch\\n' >&2");
        line(script, "  exit 20");
        line(script, "fi");
    }

    private static void appendProviderStage(StringBuilder script,
                                            DirectKernelRegistry.Match match) {
        assignment(script, "expected_provider_sha256", match.target.provider.sha256);
        line(script, "payload=\"$bundle/provider\"");
        line(script, "if ! run-as df.root cat \"$private_payload\" > \"$payload\"; then");
        line(script, "  printf 'BLOCKED: could not stage provider through package identity\\n' >&2");
        line(script, "  exit 20");
        line(script, "fi");
        appendHashGuard(script, "$payload", "$expected_provider_sha256", "provider");
        line(script, "chmod 700 \"$payload\" || exit 20");
        line(script, "if ! command -v timeout >/dev/null 2>&1; then");
        line(script, "  printf 'BLOCKED: bounded provider execution requires timeout(1)\\n' >&2");
        line(script, "  exit 20");
        line(script, "fi");
    }

    private static void appendSupportStage(StringBuilder script,
                                           DirectKernelRegistry.Match match) {
        for (ProviderBundle.Entry entry : match.supportFiles) {
            DirectKernelTarget.SupportFile support = entry.support;
            String destination = "$bundle/" + support.file;
            line(script, "if ! run-as df.root cat " + quote(entry.privateFile.getAbsolutePath())
                    + " > \"" + destination + "\"; then");
            line(script, "  printf 'BLOCKED: could not stage support file %s\\n' "
                    + quote(support.file) + " >&2");
            line(script, "  exit 20");
            line(script, "fi");
            assignment(script, "expected_support_sha256", support.sha256);
            appendHashGuard(script, destination, "$expected_support_sha256",
                    support.file);
            line(script, "chmod " + (support.executable ? "700" : "600")
                    + " \"" + destination + "\" || exit 20");
        }
    }

    private static void appendHashGuard(StringBuilder script, String path,
                                        String expected, String label) {
        line(script, "set -- $(sha256sum \"" + path + "\")");
        line(script, "observed_sha256=\"${1:-missing}\"");
        line(script, "if [ \"$observed_sha256\" != \"" + expected + "\" ]; then");
        line(script, "  printf 'BLOCKED: " + label
                + " SHA-256 mismatch observed=%s expected=%s\\n' \"$observed_sha256\" \""
                + expected + "\" >&2");
        line(script, "  exit 20");
        line(script, "fi");
        line(script, "printf 'staged " + label + ": sha256=exact\\n'");
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

    private static void appendProviderProbe(StringBuilder script,
                                            DirectKernelTarget target) {
        line(script, "probe_output=\"$(timeout '" + target.probe.timeoutSeconds
                + "' \"$payload\""
                + arguments(target.probe.arguments) + " 2>&1)\"");
        line(script, "probe_status=$?");
        line(script, "printf '%s\\n' \"$probe_output\"");
        line(script, "if [ \"$probe_status\" -ne 0 ]; then");
        line(script, "  printf 'BLOCKED: provider probe exit=%s\\n' \"$probe_status\" >&2");
        line(script, "  exit 23");
        line(script, "fi");
        for (String marker : target.probe.successMarkers) {
            line(script, "printf '%s\\n' \"$probe_output\" | grep -Fq " + quote(marker));
            line(script, "if [ $? -ne 0 ]; then printf 'BLOCKED: provider probe marker missing: %s\\n' "
                    + quote(marker) + " >&2; exit 23; fi");
        }
    }

    private static void appendStageOnlyGuard(StringBuilder script) {
        line(script, "if [ \"${DFROOT_STAGE_ONLY:-0}\" = 1 ]; then");
        line(script, "  printf 'provider staging and probe verified; live run skipped\\n'");
        line(script, "  exit 0");
        line(script, "fi");
    }

    private static void appendProviderRun(StringBuilder script,
                                          DirectKernelTarget target) {
        DirectKernelTarget.Run run = target.run;
        for (Map.Entry<String, String> entry : run.environment.entrySet())
            line(script, "export " + entry.getKey() + "=" + quote(entry.getValue()));
        assignment(script, "run_log", "/data/local/tmp/dfroot-provider-" + target.id + ".log");
        line(script, "attempt=1");
        line(script, "while [ \"$attempt\" -le '" + run.maximumAttempts + "' ]; do");
        line(script, "  printf 'direct-kernel shell attempt %s/%s; log=%s\\n' \"$attempt\" '"
                + run.maximumAttempts + "' \"$run_log\"");
        line(script, "  provider_output=\"$(timeout '" + run.startupTimeoutSeconds
                + "' \"$payload\""
                + arguments(run.arguments) + " 2>&1)\"");
        line(script, "  provider_status=$?");
        line(script, "  printf '%s\\n' \"$provider_output\" | tee \"$run_log\"");
        line(script, "  success=1");
        for (String marker : run.successMarkers) {
            line(script, "  grep -Fq " + quote(marker) + " \"$run_log\"");
            line(script, "  if [ $? -ne 0 ]; then success=0; printf 'provider success marker missing: %s\\n' "
                    + quote(marker) + " >&2; fi");
        }
        line(script, "  if [ \"$provider_status\" -eq 0 ] && [ \"$success\" -eq 1 ]; then");
        line(script, "    printf 'direct-kernel provider markers: exact\\n'");
        line(script, "    exit 0");
        line(script, "  fi");
        line(script, "  retryable=0");
        for (String marker : run.retryableMarkers) {
            line(script, "  grep -Fq " + quote(marker) + " \"$run_log\"");
            line(script, "  if [ $? -eq 0 ]; then retryable=1; fi");
        }
        line(script, "  printf 'direct-kernel shell exit=%s success=%s retryable_clean_failure=%s\\n' \"$provider_status\" \"$success\" \"$retryable\"");
        line(script, "  if [ \"$retryable\" -ne 1 ] || [ \"$attempt\" -ge '"
                + run.maximumAttempts + "' ]; then");
        line(script, "    if [ \"$provider_status\" -ne 0 ]; then exit \"$provider_status\"; fi");
        line(script, "    exit 24");
        line(script, "  fi");
        line(script, "  attempt=$((attempt + 1))");
        line(script, "  printf 'retrying only after the exact guarded allocator-exhaustion marker\\n'");
        line(script, "  sleep '" + Math.max(1, (run.retryDelayMs + 999) / 1000) + "'");
        line(script, "done");
    }

    private static String arguments(List<String> values) {
        StringBuilder result = new StringBuilder();
        for (String value : values) {
            result.append(' ');
            if (value.equals("{bundle}")) {
                result.append("\"$bundle\"");
            } else if (value.startsWith("{bundle}/")
                    && value.substring(9).matches("[A-Za-z0-9._-]+")) {
                result.append("\"$bundle\"/").append(quote(value.substring(9)));
            } else {
                result.append(quote(value));
            }
        }
        return result.toString();
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
