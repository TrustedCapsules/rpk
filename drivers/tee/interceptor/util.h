#ifndef INTERCEPTOR_UTIL_H
#define INTERCEPTOR_UTIL_H

#include <linux/version.h>

#define PROC_V    "/proc/version"
#define BOOT_PATH "/boot/System.map-"
#define MAX_VERSION_LEN   256

int find_sys_call_table(char *kern_ver, unsigned long long **sys_call_table);
char *acquire_kernel_version(char *buf);

#endif /* INTERCEPTOR_UTIL_H */
