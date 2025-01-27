/* This is educational code.
	 If you use it, please attribute it to:
	 Virtual Square wiki.virtualsquare.org */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <purelibc.h>
#include <dlfcn.h>
static sfun _native_syscall;
static char hosts[]="/etc/hostname";
static char buf[128];
static long int mysc(long int sysno, ...){
	va_list ap;
	long int a1,a2,a3,a4,a5,a6;
	va_start (ap, sysno);
	a1=va_arg(ap,long int);
	a2=va_arg(ap,long int);
	a3=va_arg(ap,long int);
	a4=va_arg(ap,long int);
	a5=va_arg(ap,long int);
	a6=va_arg(ap,long int);
	va_end(ap);
	if (sysno == __NR_open) {
		char *path=(char *)a1;
		if (a1 && strcmp(path,"/etc/passwd")==0)
			a1=(long int) hosts;
	}
	return _native_syscall(sysno,a1,a2,a3,a4,a5,a6);
}
	void
	__attribute ((constructor))
init_test (void)
{
	_native_syscall=_pure_start(mysc,0);
}

