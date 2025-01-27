/* This is educational code.
	 If you use it, please attribute it to:
	 Virtual Square wiki.virtualsquare.org */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <purelibc.h>

char *hostname = "/etc/hostname";

static sfun _native_syscall;

//static char buf[128];
static long int mysc(long int sysno, ...){
	va_list ap;
	long int a1,a2,a3,a4,a5,a6;
	va_start (ap, sysno);
	//snprintf(buf,128,"SC=%d\n",sysno);
	//_native_syscall(__NR_write,2,buf,strlen(buf));
	a1=va_arg(ap,long int);
	a2=va_arg(ap,long int);
	a3=va_arg(ap,long int);
	a4=va_arg(ap,long int);
	a5=va_arg(ap,long int);
	a6=va_arg(ap,long int);
	va_end(ap);
	if (sysno == __NR_openat &&
			strcmp((char *) a2, "/etc/passwd") == 0)
		a2 = (uintptr_t) hostname;
	if (sysno == __NR_open &&
			strcmp((char *) a1, "/etc/passwd") == 0)
		a1 = (uintptr_t) hostname;
	return _native_syscall(sysno,a1,a2,a3,a4,a5,a6);
}

void mycat(char *path) {
  int fd = open(path, O_RDONLY);
  char buf[1024];
  int n;
  while ((n = read(fd, buf, 1024)) > 0)
    write(STDOUT_FILENO, buf, n);
  close(fd);
}

int main(int argc, char*argv[]) {
	int c;
	_native_syscall=_pure_start(mysc,PUREFLAG_STDALL);
	mycat(argv[1]);
	return 0;
}
