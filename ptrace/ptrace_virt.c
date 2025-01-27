/* This is educational code.
	 If you use it, please attribute it to:
	 Virtual Square wiki.virtualsquare.org */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/user.h>   
#include <sys/reg.h>
#include <asm/ptrace-abi.h>
#include <sys/uio.h>

int main(int argc,char *argv[])
{   pid_t child;
	long orig_rax;
	child = fork();
	if(child == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		raise(SIGSTOP);
		execvp(argv[1],argv+1);
	}
	else {
		int status;
		pid_t pid;
		if ((pid=waitpid(-1,&status,0)) < 0)
			return 0;
		ptrace(PTRACE_SYSCALL, child, NULL, NULL);
		while (1) {
			if ((pid=waitpid(-1,&status,0)) < 0)
				return 0;
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
			ptrace(PTRACE_SYSCALL, child, NULL, NULL);
		}
	}
	return 0;
}

