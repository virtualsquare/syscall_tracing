/* This is educational code.
	 If you use it, please attribute it to:
	 Virtual Square wiki.virtualsquare.org */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <sys/user.h>   
#include <sys/reg.h> 
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <asm/ptrace-abi.h>
#include <sys/uio.h>

static struct sock_filter seccomp_filter[] = {
  BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_restart_syscall, 0, 1),
  BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),

  BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE),
};

static struct sock_fprog seccomp_prog = {
  .filter = seccomp_filter,
  .len = (unsigned short) (sizeof(seccomp_filter)/sizeof(seccomp_filter[0])),
};

int main(int argc,char *argv[])
{   
	pid_t child;
	long orig_rax;
	child = fork();
	if(child == 0) {
		raise(SIGSTOP);
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
			perror("prctl(PR_SET_NO_NEW_PRIVS)");
			return -1;
		}
		if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &seccomp_prog) == -1) {
			perror("when setting seccomp filter");
			return -1;
		}
		execvp(argv[1],argv+1);
	} else {
		int status;
		pid_t pid;
		int rv = ptrace(PTRACE_SEIZE, child, NULL, PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD);
		if ((pid=waitpid(-1,&status,0)) < 0)
			return 0;
		ptrace(PTRACE_CONT, child, NULL, NULL);
		while (1) {
			if ((pid=waitpid(-1,&status,0)) < 0) {
				return 0;
			}
			if (WIFSTOPPED(status)) {
				if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
					orig_rax = ptrace(PTRACE_PEEKUSER,
							child, sizeof(long) * ORIG_RAX,
							NULL);
					if (orig_rax == __NR_openat) {
						char path[PATH_MAX];
						unsigned long pathaddr = ptrace(PTRACE_PEEKUSER,
								child, sizeof(long) * RSI,
								NULL);
						struct iovec local[1] = {path, PATH_MAX};
						struct iovec remote[1] = {(void *)pathaddr, PATH_MAX};
						process_vm_readv(child, local, 1, remote, 1, 0);
						if (strcmp(path, "/etc/passwd") == 0) {
							char *newpath = "/etc/hostname";
							/* on the stack, below SP */
							uintptr_t stack_pointer = ptrace(PTRACE_PEEKUSER,
									child, sizeof(long) * RSP, NULL);
							uintptr_t remoteaddr = stack_pointer -
								((strlen(newpath) + 1 + 7) & ~0x7);
							struct iovec local[1] = {newpath, strlen(newpath) + 1};
							struct iovec remote[1] = {(void *)(remoteaddr), strlen(newpath) + 1};
							process_vm_writev(child, local, 1, remote, 1, 0);
							ptrace(PTRACE_POKEUSER, child, sizeof(long) * RSI, remoteaddr);
						}
					}
				}
				ptrace(PTRACE_CONT, child, NULL, NULL);
			}
		}
		return 0;
	}
}

