package df.root;

import android.os.Build;
import android.system.Os;

final class DirectKernelIdentity {
    final String incremental;
    final String fingerprint;
    final String device;
    final String securityPatch;
    final String kernelRelease;

    private DirectKernelIdentity(String incremental, String fingerprint,
                                 String device, String securityPatch,
                                 String kernelRelease) {
        this.incremental = incremental;
        this.fingerprint = fingerprint;
        this.device = device;
        this.securityPatch = securityPatch;
        this.kernelRelease = kernelRelease;
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
        return expected.buildIncremental.equals(incremental)
                && expected.buildFingerprint.equals(fingerprint)
                && expected.device.equals(device)
                && expected.securityPatch.equals(securityPatch)
                && expected.kernelRelease.equals(kernelRelease);
    }

    void report(IReporter reporter) {
        reporter.report("direct-kernel identity: device=" + device
                + " incremental=" + incremental
                + " security_patch=" + securityPatch
                + " kernel_release=" + kernelRelease
                + " fingerprint=" + fingerprint + "\n");
    }
}
