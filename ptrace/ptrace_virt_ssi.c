/* This is educational code.
	 If you use it, please attribute it to:
	 Virtual Square wiki.virtualsquare.org */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/user.h>   
#include <sys/reg.h>
#include <sys/uio.h>

#ifndef PTRACE_SET_SYSCALL_INFO
#define PTRACE_SET_SYSCALL_INFO              0x4212
#endif

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
		ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_O_TRACESYSGOOD);
		ptrace(PTRACE_SYSCALL, child, NULL, NULL);
		while (1) {
			if ((pid=waitpid(-1,&status,0)) < 0)
				return 0;
			struct ptrace_syscall_info psi = {0};
			ptrace(PTRACE_GET_SYSCALL_INFO, child, (void *) sizeof(psi), &psi);
			if (psi.op == PTRACE_SYSCALL_INFO_ENTRY) {
				if (psi.entry.nr == __NR_openat) {
					char path[PATH_MAX];
					struct iovec local[1] = {path, PATH_MAX};
					struct iovec remote[1] = {(void *)(psi.entry.args[1]), PATH_MAX};
					process_vm_readv(child, local, 1, remote, 1, 0);
					if (strcmp(path, "/etc/passwd") == 0) {
						char *newpath = "/etc/hostname";
						/* on the stack, below SP */
						uintptr_t remoteaddr = psi.stack_pointer - 
							((strlen(newpath) + 1 + 7) & ~0x7);
						local[0].iov_base = newpath;
						remote[0].iov_base = (void *) remoteaddr;
						local[0].iov_len = remote[0].iov_len = strlen(newpath) + 1;
						process_vm_writev(child, local, 1, remote, 1, 0);
						psi.entry.args[1] = remoteaddr;
						ptrace(PTRACE_SET_SYSCALL_INFO, child, (void *) sizeof(psi), &psi);
					}
				}
			}
			ptrace(PTRACE_SYSCALL, child, NULL, NULL);
		}
	}
	return 0;
}
