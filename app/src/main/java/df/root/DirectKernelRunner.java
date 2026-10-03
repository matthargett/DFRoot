package df.root;

import android.content.Context;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

final class DirectKernelRunner {
    private static final String ANSI = "\\x1b\\[[0-9;]*m";

    private DirectKernelRunner() {}

    static boolean probe(Context context, DirectKernelRegistry.Match match,
                         IReporter reporter)
            throws Exception {
        DirectKernelTarget target = match.target;
        DirectKernelTarget.Probe probe = target.probe;
        reporter.report("direct-kernel provider probe: target=" + target.id
                + " timeout=" + probe.timeoutSeconds + "s\n");
        MarkerState markers = new MarkerState(probe.successMarkers,
                java.util.Collections.emptyList(), java.util.Collections.emptyList());
        Process process = start(match, probe.arguments,
                java.util.Collections.emptyMap());
        Thread output = collect(process, reporter, markers, "probe");
        boolean exited = process.waitFor(probe.timeoutSeconds, TimeUnit.SECONDS);
        if (!exited) {
            process.destroyForcibly();
            output.join(2000);
            reporter.report("direct-kernel provider probe failed: timed out\n");
            return false;
        }
        output.join(2000);
        boolean exact = process.exitValue() == 0 && markers.allProbeMarkersSeen();
        reporter.report("direct-kernel provider probe result: exit=" + process.exitValue()
                + " exact_markers=" + markers.probeMarkerCount() + "/"
                + probe.successMarkers.size() + " verdict="
                + (exact ? "exact" : "failed_or_ambiguous") + "\n");
        if (exact && "shell".equals(target.run.executionDomain))
            DirectKernelShellLauncher.write(context, match, reporter);
        return exact;
    }

    static int run(Context context, DirectKernelRegistry.Match match,
                   IReporter reporter) throws Exception {
        DirectKernelTarget target = match.target;
        DirectKernelTarget.Run run = target.run;
        if (!probe(context, match, reporter)) {
            reporter.report("direct-kernel exploit blocked: provider probe did not prove the declared target\n");
            return ExploitRunner.RESULT_PROBE_FAILED;
        }
        if ("shell".equals(run.executionDomain)) {
            reporter.report("direct-kernel exploit blocked in app domain: "
                    + run.executionDomainReason + "\n");
            reporter.report("NEXT: use the printed ADB shell launcher; it rechecks identity, provider hash, PFN range, and dry markers before execution\n");
            return ExploitRunner.RESULT_INTERACTION_REQUIRED;
        }

        for (int attempt = 1; attempt <= run.maximumAttempts; attempt++) {
            reporter.report("direct-kernel attempt " + attempt + "/"
                    + run.maximumAttempts + " target=" + target.id + "\n");
            MarkerState markers = new MarkerState(
                    java.util.Collections.emptyList(), run.successMarkers,
                    run.retryableMarkers);
            Process process = start(match, run.arguments,
                    run.environment);
            Thread output = collect(process, reporter, markers, "run");
            long deadline = System.nanoTime()
                    + TimeUnit.SECONDS.toNanos(run.startupTimeoutSeconds);
            while (process.isAlive() && !markers.success.get()
                    && System.nanoTime() < deadline) {
                process.waitFor(1, TimeUnit.SECONDS);
            }

            if (markers.success.get()) {
                reporter.report("direct-kernel provider reported root; holder process remains attached\n");
                reporter.report("VERIFY: open a fresh ADB shell and record id, id -Z, SELinux state, and adbd credentials\n");
                int exit = process.waitFor();
                output.join(2000);
                reporter.report("direct-kernel holder exited code=" + exit
                        + "; in-memory root may no longer persist\n");
                return 1;
            }

            if (process.isAlive()) {
                process.destroyForcibly();
                output.join(2000);
                reporter.report("direct-kernel attempt timed out before a success marker; verdict=failed_or_ambiguous\n");
                return 2;
            }

            int exit = process.exitValue();
            output.join(2000);
            boolean retryable = markers.retryable.get();
            reporter.report("direct-kernel attempt exited code=" + exit
                    + " retryable_clean_failure=" + (retryable ? 1 : 0) + "\n");
            if (!retryable || attempt == run.maximumAttempts) return 2;
            reporter.report("retrying only because the exact provider reported its guarded allocator-exhaustion marker\n");
            Thread.sleep(run.retryDelayMs);
        }
        return 2;
    }

    private static Process start(DirectKernelRegistry.Match match, List<String> arguments,
                                 Map<String, String> environment) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(match.payload.getAbsolutePath());
        command.addAll(arguments);
        ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
        builder.environment().putAll(environment);
        builder.directory(match.payload.getParentFile());
        return builder.start();
    }

    private static Thread collect(Process process, IReporter reporter,
                                  MarkerState markers, String phase) {
        Thread thread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    process.getInputStream(), StandardCharsets.UTF_8))) {
                for (String line; (line = reader.readLine()) != null; ) {
                    String clean = line.replaceAll(ANSI, "");
                    markers.observe(clean);
                    reporter.report("direct-kernel " + phase + ": " + clean + "\n");
                }
            } catch (Exception error) {
                reporter.report("direct-kernel " + phase
                        + " output error: " + error + "\n");
            }
        }, "direct-kernel-" + phase + "-output");
        thread.start();
        return thread;
    }

    private static final class MarkerState {
        private final List<String> probeMarkers;
        private final boolean[] probeSeen;
        private final List<String> successMarkers;
        private final boolean[] successSeen;
        private final List<String> retryableMarkers;
        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicBoolean retryable = new AtomicBoolean(false);

        MarkerState(List<String> probeMarkers, List<String> successMarkers,
                    List<String> retryableMarkers) {
            this.probeMarkers = probeMarkers;
            this.probeSeen = new boolean[probeMarkers.size()];
            this.successMarkers = successMarkers;
            this.successSeen = new boolean[successMarkers.size()];
            this.retryableMarkers = retryableMarkers;
        }

        synchronized void observe(String line) {
            for (int i = 0; i < probeMarkers.size(); i++)
                if (line.contains(probeMarkers.get(i))) probeSeen[i] = true;
            for (int i = 0; i < successMarkers.size(); i++)
                if (line.contains(successMarkers.get(i))) successSeen[i] = true;
            boolean allSuccess = successSeen.length > 0;
            for (boolean seen : successSeen) allSuccess &= seen;
            success.set(allSuccess);
            for (String marker : retryableMarkers)
                if (line.contains(marker)) retryable.set(true);
        }

        synchronized boolean allProbeMarkersSeen() {
            for (boolean seen : probeSeen) if (!seen) return false;
            return true;
        }

        synchronized int probeMarkerCount() {
            int count = 0;
            for (boolean seen : probeSeen) if (seen) count++;
            return count;
        }
    }
}
