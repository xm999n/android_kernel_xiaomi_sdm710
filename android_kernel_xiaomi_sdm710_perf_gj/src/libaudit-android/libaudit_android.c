#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/netlink.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "libaudit.h"

struct syscall_entry {
	int nr;
	const char *name;
};

static const struct syscall_entry syscall_table[] = {
#include "android_aarch64_syscalls.inc"
};

int audit_open(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_AUDIT);

	if (fd < 0 && errno == EINVAL) {
		fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_AUDIT);
		if (fd >= 0)
			fcntl(fd, F_SETFD, FD_CLOEXEC);
	}

	return fd;
}

int audit_detect_machine(void)
{
	return AUDIT_ARCH_AARCH64;
}

const char *audit_errno_to_name(int error)
{
	switch (error) {
	case 0: return "SUCCESS";
	case EPERM: return "EPERM";
	case ENOENT: return "ENOENT";
	case ESRCH: return "ESRCH";
	case EINTR: return "EINTR";
	case EIO: return "EIO";
	case ENXIO: return "ENXIO";
	case E2BIG: return "E2BIG";
	case ENOEXEC: return "ENOEXEC";
	case EBADF: return "EBADF";
	case ECHILD: return "ECHILD";
	case EAGAIN: return "EAGAIN";
	case ENOMEM: return "ENOMEM";
	case EACCES: return "EACCES";
	case EFAULT: return "EFAULT";
	case EBUSY: return "EBUSY";
	case EEXIST: return "EEXIST";
	case EXDEV: return "EXDEV";
	case ENODEV: return "ENODEV";
	case ENOTDIR: return "ENOTDIR";
	case EISDIR: return "EISDIR";
	case EINVAL: return "EINVAL";
	case ENFILE: return "ENFILE";
	case EMFILE: return "EMFILE";
	case ENOTTY: return "ENOTTY";
	case ETXTBSY: return "ETXTBSY";
	case EFBIG: return "EFBIG";
	case ENOSPC: return "ENOSPC";
	case ESPIPE: return "ESPIPE";
	case EROFS: return "EROFS";
	case EMLINK: return "EMLINK";
	case EPIPE: return "EPIPE";
	case EDOM: return "EDOM";
	case ERANGE: return "ERANGE";
	case ENOSYS: return "ENOSYS";
	default: return "UNKNOWN";
	}
}

const char *audit_syscall_to_name(int sc, int machine)
{
	size_t i;

	if (machine != AUDIT_ARCH_AARCH64)
		return NULL;

	for (i = 0; i < sizeof(syscall_table) / sizeof(syscall_table[0]); ++i) {
		if (syscall_table[i].nr == sc)
			return syscall_table[i].name;
	}

	return NULL;
}

int audit_name_to_syscall(const char *sc, int machine)
{
	size_t i;

	if (machine != AUDIT_ARCH_AARCH64 || sc == NULL)
		return -1;

	for (i = 0; i < sizeof(syscall_table) / sizeof(syscall_table[0]); ++i) {
		if (strcmp(syscall_table[i].name, sc) == 0)
			return syscall_table[i].nr;
	}

	return -1;
}
