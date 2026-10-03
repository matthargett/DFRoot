package df.root;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

final class DirectKernelTarget {
    final String id;
    final Identity identity;
    final Provider provider;
    final PhysicalRange physicalRange;
    final Probe probe;
    final Run run;

    private DirectKernelTarget(String id, Identity identity, Provider provider,
                               PhysicalRange physicalRange, Probe probe, Run run) {
        this.id = id;
        this.identity = identity;
        this.provider = provider;
        this.physicalRange = physicalRange;
        this.probe = probe;
        this.run = run;
    }

    static DirectKernelTarget parse(JSONObject json) throws JSONException {
        String id = json.getString("id");
        if (!id.matches("[A-Za-z0-9._-]+"))
            throw new JSONException("invalid target id: " + id);
        return new DirectKernelTarget(
                id,
                parseIdentity(json),
                parseProvider(json.getJSONObject("payload")),
                parsePhysicalRange(json.optJSONObject("physical_pfn_range")),
                parseProbe(json.getJSONObject("probe")),
                parseRun(json.getJSONObject("run")));
    }

    private static Identity parseIdentity(JSONObject json) throws JSONException {
        String incremental = json.getString("build_incremental");
        String fingerprint = json.getString("build_fingerprint");
        String device = json.getString("device");
        String securityPatch = json.getString("security_patch");
        String kernelRelease = json.getString("kernel_release");
        if (incremental.isEmpty() || fingerprint.isEmpty() || device.isEmpty()
                || securityPatch.isEmpty() || kernelRelease.isEmpty())
            throw new JSONException("identity fields must be nonempty");
        return new Identity(incremental, fingerprint, device, securityPatch,
                kernelRelease);
    }

    private static Provider parseProvider(JSONObject json) throws JSONException {
        String file = json.getString("file");
        String sha256 = json.getString("sha256").toLowerCase(Locale.ROOT);
        if (!file.matches("libdfroot_[A-Za-z0-9_]+\\.so"))
            throw new JSONException("invalid provider filename: " + file);
        if (!sha256.matches("[0-9a-f]{64}"))
            throw new JSONException("invalid provider SHA-256");
        return new Provider(file, sha256);
    }

    private static PhysicalRange parsePhysicalRange(JSONObject json)
            throws JSONException {
        if (json == null) return null;
        String permissionPolicy = json.optString(
                "on_app_permission_denied", "reject");
        if (!"reject".equals(permissionPolicy)
                && !"use_descriptor".equals(permissionPolicy))
            throw new JSONException("invalid PFN permission policy: "
                    + permissionPolicy);

        long start = parseLong(json.getString("observed_start"));
        long unalignedEnd = parseLong(json.getString("observed_unaligned_end"));
        long configuredEnd = parseLong(json.getString("configured_end"));
        long segmentPages = parseLong(json.getString("segment_pages"));
        int groups = json.getInt("groups");
        long span = configuredEnd - start;
        if (start < 0 || unalignedEnd <= start || configuredEnd < unalignedEnd
                || segmentPages <= 0 || groups <= 0 || span <= 0
                || span % segmentPages != 0 || span / segmentPages != groups)
            throw new JSONException("invalid physical PFN range");
        return new PhysicalRange(start, unalignedEnd, configuredEnd, groups,
                segmentPages, "use_descriptor".equals(permissionPolicy));
    }

    private static Probe parseProbe(JSONObject json) throws JSONException {
        List<String> arguments = strings(json.getJSONArray("arguments"));
        List<String> successMarkers = strings(json.getJSONArray("success_markers"));
        if (successMarkers.isEmpty())
            throw new JSONException("probe success markers must be nonempty");
        return new Probe(arguments, successMarkers,
                positive(json, "timeout_seconds"));
    }

    private static Run parseRun(JSONObject json) throws JSONException {
        String executionDomain = json.optString("execution_domain", "app");
        if (!"app".equals(executionDomain) && !"shell".equals(executionDomain))
            throw new JSONException("invalid execution domain: " + executionDomain);
        String executionDomainReason = json.optString("execution_domain_reason", "");
        if ("shell".equals(executionDomain) && executionDomainReason.isEmpty())
            throw new JSONException("shell execution domain requires a reason");

        int maximumAttempts = positive(json, "maximum_attempts");
        if (maximumAttempts > 3)
            throw new JSONException("maximum_attempts must be <= 3");
        List<String> successMarkers = strings(json.getJSONArray("success_markers"));
        if (successMarkers.isEmpty())
            throw new JSONException("run success markers must be nonempty");
        return new Run(
                environment(json.getJSONObject("environment")),
                successMarkers,
                strings(json.getJSONArray("retryable_markers")),
                executionDomain,
                executionDomainReason,
                positive(json, "startup_timeout_seconds"),
                maximumAttempts,
                positive(json, "retry_delay_ms"));
    }

    private static Map<String, String> environment(JSONObject json)
            throws JSONException {
        Map<String, String> values = new LinkedHashMap<>();
        Iterator<String> keys = json.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (!key.matches("[A-Z][A-Z0-9_]*"))
                throw new JSONException("invalid environment name: " + key);
            values.put(key, json.getString(key));
        }
        return Collections.unmodifiableMap(values);
    }

    private static List<String> strings(JSONArray array) throws JSONException {
        List<String> values = new ArrayList<>();
        for (int i = 0; i < array.length(); i++) {
            String value = array.getString(i);
            if (value.isEmpty()) throw new JSONException("empty list value");
            values.add(value);
        }
        return Collections.unmodifiableList(values);
    }

    private static int positive(JSONObject json, String name) throws JSONException {
        int value = json.getInt(name);
        if (value <= 0) throw new JSONException(name + " must be positive");
        return value;
    }

    private static long parseLong(String value) throws JSONException {
        try {
            return Long.decode(value);
        } catch (NumberFormatException error) {
            throw new JSONException("invalid integer: " + value);
        }
    }

    static final class Identity {
        final String buildIncremental;
        final String buildFingerprint;
        final String device;
        final String securityPatch;
        final String kernelRelease;

        Identity(String buildIncremental, String buildFingerprint, String device,
                 String securityPatch, String kernelRelease) {
            this.buildIncremental = buildIncremental;
            this.buildFingerprint = buildFingerprint;
            this.device = device;
            this.securityPatch = securityPatch;
            this.kernelRelease = kernelRelease;
        }
    }

    static final class Provider {
        final String file;
        final String sha256;

        Provider(String file, String sha256) {
            this.file = file;
            this.sha256 = sha256;
        }
    }

    static final class PhysicalRange {
        final long observedStart;
        final long observedUnalignedEnd;
        final long configuredEnd;
        final int groups;
        final long segmentPages;
        final boolean allowDescriptorOnPermissionDenied;

        PhysicalRange(long observedStart, long observedUnalignedEnd,
                      long configuredEnd, int groups, long segmentPages,
                      boolean allowDescriptorOnPermissionDenied) {
            this.observedStart = observedStart;
            this.observedUnalignedEnd = observedUnalignedEnd;
            this.configuredEnd = configuredEnd;
            this.groups = groups;
            this.segmentPages = segmentPages;
            this.allowDescriptorOnPermissionDenied =
                    allowDescriptorOnPermissionDenied;
        }
    }

    static final class Probe {
        final List<String> arguments;
        final List<String> successMarkers;
        final int timeoutSeconds;

        Probe(List<String> arguments, List<String> successMarkers,
              int timeoutSeconds) {
            this.arguments = arguments;
            this.successMarkers = successMarkers;
            this.timeoutSeconds = timeoutSeconds;
        }
    }

    static final class Run {
        final Map<String, String> environment;
        final List<String> successMarkers;
        final List<String> retryableMarkers;
        final String executionDomain;
        final String executionDomainReason;
        final int startupTimeoutSeconds;
        final int maximumAttempts;
        final int retryDelayMs;

        Run(Map<String, String> environment, List<String> successMarkers,
            List<String> retryableMarkers, String executionDomain,
            String executionDomainReason, int startupTimeoutSeconds,
            int maximumAttempts, int retryDelayMs) {
            this.environment = environment;
            this.successMarkers = successMarkers;
            this.retryableMarkers = retryableMarkers;
            this.executionDomain = executionDomain;
            this.executionDomainReason = executionDomainReason;
            this.startupTimeoutSeconds = startupTimeoutSeconds;
            this.maximumAttempts = maximumAttempts;
            this.retryDelayMs = retryDelayMs;
        }
    }
}
