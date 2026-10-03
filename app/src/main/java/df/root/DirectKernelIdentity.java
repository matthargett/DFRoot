package df.root;

import android.os.Build;
import android.system.Os;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

final class DirectKernelIdentity {
    final String incremental;
    final String fingerprint;
    final String device;
    final String securityPatch;
    final String kernelRelease;
    final String sha256;

    private DirectKernelIdentity(String incremental, String fingerprint,
                                 String device, String securityPatch,
                                 String kernelRelease) {
        this.incremental = incremental;
        this.fingerprint = fingerprint;
        this.device = device;
        this.securityPatch = securityPatch;
        this.kernelRelease = kernelRelease;
        this.sha256 = digest(fingerprint, incremental, securityPatch,
                kernelRelease);
    }

    static DirectKernelIdentity observe() {
        return new DirectKernelIdentity(
                Build.VERSION.INCREMENTAL,
                Build.FINGERPRINT,
                Build.DEVICE,
                Build.VERSION.SECURITY_PATCH,
                Os.uname().release);
    }

    boolean matches(DirectKernelTarget target) {
        DirectKernelTarget.Identity expected = target.identity;
        if (expected.sha256 != null) return expected.sha256.equals(sha256);
        return expected.buildIncremental.equals(incremental)
                && expected.buildFingerprint.equals(fingerprint)
                && expected.device.equals(device)
                && expected.securityPatch.equals(securityPatch)
                && expected.kernelRelease.equals(kernelRelease);
    }

    void report(IReporter reporter) {
        reporter.report("direct-kernel identity: sha256=" + sha256
                + " incremental=" + incremental
                + " security_patch=" + securityPatch
                + " kernel_release=" + kernelRelease + "\n");
    }

    private static String digest(String fingerprint, String incremental,
                                 String securityPatch, String kernelRelease) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String canonical = fingerprint + "\n" + incremental + "\n"
                    + securityPatch + "\n" + kernelRelease + "\n";
            StringBuilder hex = new StringBuilder(64);
            for (byte value : digest.digest(canonical.getBytes(StandardCharsets.UTF_8)))
                hex.append(String.format(Locale.ROOT, "%02x", value & 0xff));
            return hex.toString();
        } catch (Exception error) {
            throw new IllegalStateException("SHA-256 unavailable", error);
        }
    }
}
