#ifndef DFROOT_PAYLOADS_H
#define DFROOT_PAYLOADS_H

#include <stdint.h>

enum KoCompletion {
    KO_LAUNCHES_KSUD = 0,
    KO_MAKES_SELINUX_PERMISSIVE = 1,
};

struct KoImage {
    const char *id;
    const char *kernel_release;
    int android_release;
    int kernel_major;
    int kernel_minor;
    enum KoCompletion completion;
    const char *start;
    const char *end;
};

const struct KoImage *select_ko_image(int android_release,
                                      int kernel_major, int kernel_minor);
const struct KoImage *select_runtime_ko_image(void);
int read_device_versions(int *android_release,
                         int *kernel_major, int *kernel_minor);

extern char splice_helper_start[];
extern char splice_helper_end[];

extern char init_shell_start[];
extern char init_shell_data[];
extern char init_shell_first_inst_copy[];
extern uint32_t init_shell_len;

extern char libcxx_start[];
extern char libcxx_data[];
extern char libcxx_first_inst_copy[];
extern uint32_t libcxx_len;
extern uint32_t libcxx_ko_target_off;
extern uint32_t libcxx_soft_reboot_off;

#endif
