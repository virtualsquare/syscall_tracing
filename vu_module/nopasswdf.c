/* This is educational code.
	 If you use it, please attribute it to:
	 Virtual Square wiki.virtualsquare.org */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <vumodule.h>
#include <errno.h>

VU_PROTOTYPES(nopasswd)

	struct vu_module_t vu_module = {
		.name = "nopasswd",
		.description = "map /etc/passwd to /etc/hostname",
		.flags = VU_USE_PRW
	};

int vu_nopasswd_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count, void *private) {
	return syscall(__NR_getdents64, fd, dirp, count);
}

static struct vuht_entry_t *ht;

void vu_nopasswd_cleanup(uint8_t type, void *arg, int arglen,
    struct vuht_entry_t *ht) {
	if (type == CHECKPATH) {
		//printk("%*.*s\n", arglen, arglen, arg);
	}
}

int vu_nopasswd_open(const char *pathname, int flags, mode_t mode, void **fdprivate) {
	if (strcmp(pathname, "/etc/passwd") == 0)
		return open("/etc/hostname", flags, mode);
	else
		return open(pathname, flags, mode);
}

void *vu_nopasswd_init(void) {
	struct vu_service_t *s = vu_mod_getservice();

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	vu_syscall_handler(s, lstat) = lstat;
	vu_syscall_handler(s, readlink) = readlink;
	vu_syscall_handler(s, unlink) = unlink;
	vu_syscall_handler(s, mkdir) = mkdir;
	vu_syscall_handler(s, rmdir) = rmdir;
	vu_syscall_handler(s, mknod) = mknod;
	vu_syscall_handler(s, chmod) = chmod;
	vu_syscall_handler(s, lchown) = lchown;
	vu_syscall_handler(s, utimensat) = utimensat;
	vu_syscall_handler(s, symlink) = symlink;
	vu_syscall_handler(s, link) = link;
	vu_syscall_handler(s, rename) = rename;
	vu_syscall_handler(s, truncate) = truncate;
	vu_syscall_handler(s, statfs) = statfs;
	vu_syscall_handler(s, lgetxattr) = lgetxattr;
	vu_syscall_handler(s, lsetxattr) = lsetxattr;
	vu_syscall_handler(s, llistxattr) = llistxattr;

	vu_syscall_handler(s, close) = close;
	vu_syscall_handler(s, pread64) = pread;
	vu_syscall_handler(s, pwrite64) = pwrite;
	vu_syscall_handler(s, fcntl) = fcntl;
#pragma GCC diagnostic pop

	ht = vuht_pathadd(CHECKPATH,"/","/","nopasswd",0,"",s,0,NULL,NULL);
	return NULL;
}

int vu_nopasswd_fini(void *private) {
	if (ht && vuht_del(ht, MNT_FORCE) == 0)
		ht = NULL;
	return 0;
}
