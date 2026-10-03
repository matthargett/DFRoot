#include "payloads.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

asm(
    ".section .rodata\n"
    ".global dirtyfrag_ko_12_5_10_start\n.global dirtyfrag_ko_12_5_10_end\n"
    "dirtyfrag_ko_12_5_10_start:\n.incbin \"ko/dirtyfrag-android12-5.10.ko\"\ndirtyfrag_ko_12_5_10_end:\n"
    ".global dirtyfrag_ko_13_5_10_start\n.global dirtyfrag_ko_13_5_10_end\n"
    "dirtyfrag_ko_13_5_10_start:\n.incbin \"ko/dirtyfrag-android13-5.10.ko\"\ndirtyfrag_ko_13_5_10_end:\n"
    ".global dirtyfrag_ko_13_5_15_start\n.global dirtyfrag_ko_13_5_15_end\n"
    "dirtyfrag_ko_13_5_15_start:\n.incbin \"ko/dirtyfrag-android13-5.15.ko\"\ndirtyfrag_ko_13_5_15_end:\n"
    ".global dirtyfrag_ko_14_5_15_start\n.global dirtyfrag_ko_14_5_15_end\n"
    "dirtyfrag_ko_14_5_15_start:\n.incbin \"ko/dirtyfrag-android14-5.15.ko\"\ndirtyfrag_ko_14_5_15_end:\n"
    ".global dirtyfrag_ko_15_6_6_start\n.global dirtyfrag_ko_15_6_6_end\n"
    "dirtyfrag_ko_15_6_6_start:\n.incbin \"ko/dirtyfrag-android15-6.6.ko\"\ndirtyfrag_ko_15_6_6_end:\n"
    ".global dirtyfrag_ko_16_6_12_start\n.global dirtyfrag_ko_16_6_12_end\n"
    "dirtyfrag_ko_16_6_12_start:\n.incbin \"ko/dirtyfrag-android16-6.12.ko\"\ndirtyfrag_ko_16_6_12_end:\n"
    ".global dirtyfrag_ko_17_6_18_start\n.global dirtyfrag_ko_17_6_18_end\n"
    "dirtyfrag_ko_17_6_18_start:\n.incbin \"ko/dirtyfrag-android17-6.18.ko\"\ndirtyfrag_ko_17_6_18_end:\n"
    ".global dirtyfrag_ko_5_10_198_exact_start\n.global dirtyfrag_ko_5_10_198_exact_end\n"
    "dirtyfrag_ko_5_10_198_exact_start:\n.incbin \"ko/dirtyfrag-5.10.198-gaaf872b28b70-ab117.ko\"\ndirtyfrag_ko_5_10_198_exact_end:\n"
    ".global splice_helper_start\n.global splice_helper_end\n"
    "splice_helper_start:\n.incbin \"splicehelper\"\nsplice_helper_end:\n"
);

extern char dirtyfrag_ko_12_5_10_start[], dirtyfrag_ko_12_5_10_end[];
extern char dirtyfrag_ko_13_5_10_start[], dirtyfrag_ko_13_5_10_end[];
extern char dirtyfrag_ko_13_5_15_start[], dirtyfrag_ko_13_5_15_end[];
extern char dirtyfrag_ko_14_5_15_start[], dirtyfrag_ko_14_5_15_end[];
extern char dirtyfrag_ko_15_6_6_start[], dirtyfrag_ko_15_6_6_end[];
extern char dirtyfrag_ko_16_6_12_start[], dirtyfrag_ko_16_6_12_end[];
extern char dirtyfrag_ko_17_6_18_start[], dirtyfrag_ko_17_6_18_end[];
extern char dirtyfrag_ko_5_10_198_exact_start[];
extern char dirtyfrag_ko_5_10_198_exact_end[];

static const struct KoImage images[] = {
    {"kernel-5.10.198-gaaf872b28b70-ab117",
     "5.10.198-perf-gaaf872b28b70-ab117", 0, 0, 0,
     KO_MAKES_SELINUX_PERMISSIVE,
     dirtyfrag_ko_5_10_198_exact_start, dirtyfrag_ko_5_10_198_exact_end},
    {"kmi-android12-5.10", NULL, 12, 5, 10, KO_LAUNCHES_KSUD,
     dirtyfrag_ko_12_5_10_start, dirtyfrag_ko_12_5_10_end},
    {"kmi-android13-5.10", NULL, 13, 5, 10, KO_LAUNCHES_KSUD,
     dirtyfrag_ko_13_5_10_start, dirtyfrag_ko_13_5_10_end},
    {"kmi-android13-5.15", NULL, 13, 5, 15, KO_LAUNCHES_KSUD,
     dirtyfrag_ko_13_5_15_start, dirtyfrag_ko_13_5_15_end},
    {"kmi-android14-5.15", NULL, 14, 5, 15, KO_LAUNCHES_KSUD,
     dirtyfrag_ko_14_5_15_start, dirtyfrag_ko_14_5_15_end},
    {"kmi-android15-6.6", NULL, 15, 6, 6, KO_LAUNCHES_KSUD,
     dirtyfrag_ko_15_6_6_start, dirtyfrag_ko_15_6_6_end},
    {"kmi-android16-6.12", NULL, 16, 6, 12, KO_LAUNCHES_KSUD,
     dirtyfrag_ko_16_6_12_start, dirtyfrag_ko_16_6_12_end},
    {"kmi-android17-6.18", NULL, 17, 6, 18, KO_LAUNCHES_KSUD,
     dirtyfrag_ko_17_6_18_start, dirtyfrag_ko_17_6_18_end},
};

const struct KoImage *select_ko_image(int android_release,
                                      int kernel_major, int kernel_minor) {
    for (size_t i = 0; i < sizeof(images) / sizeof(images[0]); i++) {
        if (!images[i].kernel_release
                && images[i].android_release == android_release
                && images[i].kernel_major == kernel_major
                && images[i].kernel_minor == kernel_minor)
            return &images[i];
    }
    return NULL;
}

const struct KoImage *select_runtime_ko_image(void) {
    struct utsname identity;
    if (uname(&identity) != 0) return NULL;
    for (size_t i = 0; i < sizeof(images) / sizeof(images[0]); i++) {
        if (images[i].kernel_release
                && strcmp(images[i].kernel_release, identity.release) == 0)
            return &images[i];
    }

    int android_release = 0, kernel_major = 0, kernel_minor = 0;
    if (read_device_versions(&android_release,
                             &kernel_major, &kernel_minor) != 0)
        return NULL;
    return select_ko_image(android_release, kernel_major, kernel_minor);
}

int read_device_versions(int *android_release,
                         int *kernel_major, int *kernel_minor) {
    struct utsname identity;
    if (uname(&identity) != 0
            || sscanf(identity.release, "%d.%d", kernel_major, kernel_minor) != 2)
        return -1;
    const char *marker = strstr(identity.release, "android");
    if (!marker) return -1;
    *android_release = atoi(marker + 7);
    return *android_release > 0 ? 0 : -1;
}
