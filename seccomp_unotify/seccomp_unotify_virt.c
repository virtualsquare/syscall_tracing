/* This is educational code.
	 If you use it, please attribute it to:
	 Virtual Square wiki.virtualsquare.org */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define ARRAY_SIZE(arr)  (sizeof(arr) / sizeof((arr)[0]))

	static void
sigchldHandler(int sig)
{
	_exit(EXIT_SUCCESS);
}

	static int
seccomp(unsigned int operation, unsigned int flags, void *args)
{
	return syscall(SYS_seccomp, operation, flags, args);
}

	static int
installNotifyFilter(void)
{
	int notifyFd;

	struct sock_filter filter[] = {
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_restart_syscall, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_USER_NOTIF),
	};

	struct sock_fprog prog = {
		.len = ARRAY_SIZE(filter),
		.filter = filter,
	};

	/* Install the filter with the SECCOMP_FILTER_FLAG_NEW_LISTENER flag;
		 as a result, seccomp() returns a notification file descriptor. */

	notifyFd = seccomp(SECCOMP_SET_MODE_FILTER,
			SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
	if (notifyFd == -1)
		err(EXIT_FAILURE, "seccomp-install-notify-filter");

	return notifyFd;
}

static int *notifyFd;

	static pid_t
targetProcess(char *argv[])
{
	int    s;
	pid_t  targetPid;
	notifyFd = mmap(NULL, sizeof *notifyFd, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	*notifyFd = -1;
	targetPid = fork();
	if (targetPid == -1)
		err(EXIT_FAILURE, "fork");
	if (targetPid > 0)          /* In parent, return PID of child */
		return targetPid;

	/* Child falls through to here */
	/* Install seccomp filter(s) */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		err(EXIT_FAILURE, "prctl");
	*notifyFd = installNotifyFilter(); /* should be close on exec */
	execvp(argv[0], argv);
	err(EXIT_FAILURE, "execvp");
}

/* Check that the notification ID provided by a SECCOMP_IOCTL_NOTIF_RECV
	 operation is still valid. It will no longer be valid if the target
	 process has terminated or is no longer blocked in the system call that
	 generated the notification (because it was interrupted by a signal).

	 This operation can be used when doing such things as accessing
	 /proc/PID files in the target process in order to avoid TOCTOU race
	 conditions where the PID that is returned by SECCOMP_IOCTL_NOTIF_RECV
	 terminates and is reused by another process. */

	static bool
cookieIsValid(int notifyFd, uint64_t id)
{
	return ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0;
}

	static bool
getTargetPathname(struct seccomp_notif *req, int notifyFd,
		int argNum, char *path, size_t len)
{
	ssize_t  nread;
	struct iovec local_iov = {path, len};
	struct iovec remote_iov = {(void *) req->data.args[argNum], PATH_MAX};
	nread = process_vm_readv(req->pid, &local_iov, 1, &remote_iov, 1, 0);
	if (nread <= 0)
    return false;
	if (!cookieIsValid(notifyFd, req->id)) {
		perror("\tS: notification ID check failed!!!");
		return false;
	}
	return true;
}

/* Handle notifications that arrive via the SECCOMP_RET_USER_NOTIF file
	 descriptor, 'notifyFd'. */
	static void
handleNotifications(int notifyFd)
{
	bool                        pathOK;
	char                        path[PATH_MAX];
	struct seccomp_notif        *req;
	struct seccomp_notif_resp   *resp;
	struct seccomp_notif_sizes  sizes;
	if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == -1)
    err(EXIT_FAILURE, "seccomp-SECCOMP_GET_NOTIF_SIZES");
	uint8_t reqbuf[sizes.seccomp_notif];
	if (sizeof(struct seccomp_notif_resp) > sizes.seccomp_notif_resp)
		sizes.seccomp_notif_resp = sizeof(struct seccomp_notif_resp);
	uint8_t respbuf[sizes.seccomp_notif_resp];
	req = (void *) reqbuf;
	resp = (void *) respbuf;

	/* Loop handling notifications */
	for (;;) {
		/* Wait for next notification, returning info in '*req' */
		memset(req, 0, sizes.seccomp_notif);
		if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_RECV, req) == -1) {
			if (errno == EINTR)
				continue;
			if (errno == ENOENT) /* workaround for race condition */
				continue;
			err(EXIT_FAILURE, "\tS: ioctl-SECCOMP_IOCTL_NOTIF_RECV");
		}

		if (req->data.nr == __NR_openat) {
			getTargetPathname(req, notifyFd, 1, path, PATH_MAX);
			if (strcmp(path, "/etc/passwd") == 0) {
				int fd = open("/etc/hostname", req->data.args[2],  req->data.args[3]);

				struct seccomp_notif_addfd respfd = {
					.id = req->id,
					.flags = SECCOMP_ADDFD_FLAG_SEND,
					.srcfd = fd
				};
				int remfd;
				remfd = ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_ADDFD, &respfd);
				if (remfd < 0)
					perror("SECCOMP_IOCTL_NOTIF_ADDFD");
				close(fd);
				continue;
			}
		} 
		resp->id = req->id;     /* Response includes notification ID */
		resp->error = resp->val = 0;
		resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

		/* Send a response to the notification */
		if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1) {
			if (errno == ENOENT)
				printf("\tS: response failed with ENOENT; "
						"perhaps target process's syscall was "
						"interrupted by a signal?\n");
			else
				perror("ioctl-SECCOMP_IOCTL_NOTIF_SEND");
		}
	}
	exit(EXIT_FAILURE);
}

	static void
supervisor(pid_t clientpid)
{
	int local_notifyFd;

	while(*notifyFd < 0)
		usleep(1000);

	int pidfd = syscall(SYS_pidfd_open, clientpid, 0);
	local_notifyFd = syscall(SYS_pidfd_getfd, pidfd, *notifyFd, 0);
	munmap(notifyFd, sizeof *notifyFd);
	close(pidfd);

	handleNotifications(local_notifyFd);
}

	int
main(int argc, char *argv[])
{
	struct sigaction  sa;

	setbuf(stdout, NULL);

	if (argc < 2) {
		fprintf(stderr, "At least one pathname argument is required\n");
		exit(EXIT_FAILURE);
	}

	pid_t clientpid = targetProcess(&argv[1]);

	/* Catch SIGCHLD when the target terminates, so that the
		 supervisor can also terminate. */
	sa.sa_handler = sigchldHandler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGCHLD, &sa, NULL) == -1)
		err(EXIT_FAILURE, "sigaction");

	supervisor(clientpid);

	exit(EXIT_SUCCESS);
}
