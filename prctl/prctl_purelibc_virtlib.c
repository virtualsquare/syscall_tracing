/* This is educational code.
	 If you use it, please attribute it to:
	 Virtual Square wiki.virtualsquare.org */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <ucontext.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
 
static __thread char selector = SYSCALL_DISPATCH_FILTER_ALLOW;

static inline void dispatcher_off(void)
{
	selector = SYSCALL_DISPATCH_FILTER_ALLOW;
}

static inline void dispatcher_on(void)
{
	selector = SYSCALL_DISPATCH_FILTER_BLOCK;
}

void *_sigret_addr;

char *hostname = "/etc/hostname";
static void handler(int num, siginfo_t *info, void *vucontext)
{
	dispatcher_off();
	struct ucontext_t *uc = vucontext;
	struct sigcontext *r=(struct sigcontext *)(&uc->uc_mcontext);
	if (info->si_syscall == __NR_openat &&
			strcmp((char *) r->rsi, "/etc/passwd") == 0) {
		r->rsi = (uintptr_t) hostname;
	}
	long retval = syscall(info->si_syscall,
			r->rdi, r->rsi, r->rdx,
			r->r10, r->r8, r->r9);
	r->rax = retval;
	dispatcher_on();
}

	void
  __attribute ((constructor))
init_test (void) {
	struct sigaction action = {
		.sa_sigaction = handler,
		.sa_flags = SA_SIGINFO
	};
	struct sigaction oldaction;
	sigfillset(&action.sa_mask);
	sigdelset(&action.sa_mask, SIGSYS);
	int ret = sigaction(SIGSYS, &action, NULL);
	if (ret < 0) {
		perror("sigaction");
		exit(1);
	}
	ret = sigaction(SIGSYS, &action, &oldaction);
	if (ret < 0) {
		perror("sigactioni old");
		exit(1);
	}
	_sigret_addr = oldaction.sa_restorer;
	ret = prctl(PR_SET_SYSCALL_USER_DISPATCH,
			    PR_SYS_DISPATCH_ON, _sigret_addr, 16, &selector);
	if (ret < 0) {
		perror("prctl");
		exit(1);
	}
	dispatcher_on();
}
