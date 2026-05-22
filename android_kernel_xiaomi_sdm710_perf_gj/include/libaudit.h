#ifndef PERF_GJ_LIBAUDIT_H
#define PERF_GJ_LIBAUDIT_H

#include <linux/audit.h>

#ifdef __cplusplus
extern "C" {
#endif

int audit_open(void);
int audit_detect_machine(void);
const char *audit_errno_to_name(int error);
const char *audit_syscall_to_name(int sc, int machine);
int audit_name_to_syscall(const char *sc, int machine);

#ifdef __cplusplus
}
#endif

#endif
