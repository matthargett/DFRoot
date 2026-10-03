package df.root;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class PhysicalMemoryProbe {
    private static final Pattern ZONE = Pattern.compile(
            "Node\\s+(\\d+),\\s+zone\\s+(.+)");
    private static final Pattern VALUE = Pattern.compile(
            "(start_pfn|spanned|present|managed)\\s*:?\\s*(\\d+)");

    static final class Zone {
        final int node;
        final String name;
        long start = -1;
        long spanned = -1;
        long present = -1;
        long managed = -1;

        Zone(int node, String name) {
            this.node = node;
            this.name = name;
        }
    }

    static final class Result {
        final List<Zone> zones;
        final long start;
        final long end;
        final String error;
        final boolean permissionDenied;

        Result(List<Zone> zones, long start, long end, String error,
               boolean permissionDenied) {
            this.zones = zones;
            this.start = start;
            this.end = end;
            this.error = error;
            this.permissionDenied = permissionDenied;
        }

        boolean readable() {
            return error == null && start >= 0 && end > start;
        }
    }

    private PhysicalMemoryProbe() {}

    static Result read() {
        List<Zone> zones = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(
                new FileReader("/proc/zoneinfo"))) {
            Zone current = null;
            for (String line; (line = reader.readLine()) != null; ) {
                Matcher zone = ZONE.matcher(line.trim());
                if (zone.matches()) {
                    current = new Zone(Integer.parseInt(zone.group(1)),
                            zone.group(2).trim());
                    zones.add(current);
                    continue;
                }
                if (current == null) continue;
                Matcher value = VALUE.matcher(line.trim());
                if (!value.matches()) continue;
                long parsed = Long.parseLong(value.group(2));
                switch (value.group(1)) {
                    case "start_pfn": current.start = parsed; break;
                    case "spanned": current.spanned = parsed; break;
                    case "present": current.present = parsed; break;
                    case "managed": current.managed = parsed; break;
                    default: break;
                }
            }
        } catch (FileNotFoundException error) {
            boolean permissionDenied = error.getMessage() != null
                    && error.getMessage().contains("EACCES");
            return new Result(zones, -1, -1, error.toString(), permissionDenied);
        } catch (Exception error) {
            return new Result(zones, -1, -1, error.toString(), false);
        }
        long start = Long.MAX_VALUE;
        long end = -1;
        for (Zone zone : zones) {
            if (zone.start < 0 || zone.spanned <= 0) continue;
            start = Math.min(start, zone.start);
            end = Math.max(end, zone.start + zone.spanned);
        }
        if (start == Long.MAX_VALUE)
            return new Result(zones, -1, -1, "no populated zones", false);
        return new Result(zones, start, end, null, false);
    }

    static boolean verify(DirectKernelTarget target, IReporter reporter) {
        DirectKernelTarget.PhysicalRange expected = target.physicalRange;
        if (expected == null) return true;
        Result result = read();
        if (!result.readable()) {
            if (result.permissionDenied
                    && expected.allowDescriptorOnPermissionDenied) {
                long span = expected.configuredEnd - expected.observedStart;
                long groups = span / expected.segmentPages;
                reporter.report("physical PFN discovery: source=/proc/zoneinfo access=permission_denied_in_app_domain\n");
                reporter.report(String.format(Locale.ROOT,
                        "physical PFN envelope: descriptor=[0x%x,0x%x) observed_unaligned_end=0x%x segment=0x%x groups=%d verdict=descriptor_only%n",
                        expected.observedStart, expected.configuredEnd,
                        expected.observedUnalignedEnd, expected.segmentPages,
                        groups));
                reporter.report("NEXT: verify /proc/zoneinfo from ADB shell against the printed descriptor before changing or reusing this target; readable mismatches remain fatal\n");
                return groups == expected.groups;
            }
            reporter.report("physical PFN discovery failed: source=/proc/zoneinfo error="
                    + result.error + "\n");
            reporter.report("candidate " + target.id
                    + " rejected: configured physical range could not be re-derived\n");
            return false;
        }
        for (Zone zone : result.zones) {
            if (zone.start < 0 || zone.spanned <= 0) continue;
            reporter.report(String.format(Locale.ROOT,
                    "physical PFN zone: node=%d name=%s start=0x%x spanned=0x%x present=0x%x managed=0x%x%n",
                    zone.node, zone.name, zone.start, zone.spanned,
                    zone.present, zone.managed));
        }
        boolean exact = result.start == expected.observedStart
                && result.end == expected.observedUnalignedEnd;
        long span = expected.configuredEnd - expected.observedStart;
        long groups = span / expected.segmentPages;
        reporter.report(String.format(Locale.ROOT,
                "physical PFN envelope: observed=[0x%x,0x%x) configured=[0x%x,0x%x) segment=0x%x groups=%d descriptor_groups=%d verdict=%s%n",
                result.start, result.end, expected.observedStart,
                expected.configuredEnd, expected.segmentPages, groups,
                expected.groups, exact ? "exact" : "mismatch"));
        if (!exact || groups != expected.groups) {
            reporter.report("candidate " + target.id
                    + " rejected: physical range evidence changed; re-derive rather than widening blindly\n");
            return false;
        }
        return true;
    }
}
