# `syscall_tracing`

## Status and Desiderata for Syscall Tracing and Virtualization Support

This repository includes the source code of the examples of the seminar
held at
[FOSDEM 2025](https://fosdem.org/2025/schedule/event/fosdem-2025-6231-status-and-desiderata-for-syscall-tracing-and-virtualization-support/).

All the programs implements the same (basic) virtualization: when a program opens the file `/etc/passwd`, the file
`/etc/hostname` is used instead.
The (educational) purpose of this work is to show how to trace process generated system calls and how to
modify their parameters.

Some methods are *hypervisor based*: there is a tracer process (named hypervisor) which is notified of system calls requests of tracee processes.

* `ptrace`: Ptrace is a system call mainly used for debugging (see strace, gdb). It has been used to implement
User-Mode Linux. Each system call request generates two events: one before the kernel processes the system call
and one after. The first event can be used to retrieve the system call arguments, and maybe modify them, the second
gives access to the return value/error number.

* `ptrace_seccomp`: It is possible to reduce the number of context switches using ptrace and seccomp together.
When the `bpf` program loaded via seccomp resturns the tag `SECCOMP_RET_TRACE` a ptrace event is generated.
In this way it is possible to select the set of traced system calls in the `bpf` program and to skip the
second event when not necessary.

* `seccomp_unotify`
(from the man page):  In conventional usage of a seccomp filter, the decision about how to treat
a  system  call is made by the filter itself.  By contrast, the user-space
notification mechanism allows the seccomp filter to delegate the  handling
of  the  system call to another user-space process.

Other methods implement *self virtualization*: the system call requests are processed by a function
of  the very same process.

* purelibc. [purelibc](https://github.com/virtualsquare/purelibc) is
an overlay library for glibc that allows system call capturing.

* prctl. (from the man page)
The `PR_SET_SYSCALL_USER_DISPATCH` tag allows configuration of the  Syscall User Dispatch  mechanism for the calling thread.
This mechanism allows an application to selectively intercept system calls
so that they can be handled within the application  itself.   Interception
takes the form of a thread-directed SIGSYS signal that is delivered to the
thread  when  it  makes a system call.  If intercepted, the system call is
not executed by the kernel.

The directory `vu_module` shows how the same *virtualization* can me implemented as a
[VUOS](https://github.com/virtualsquare/vuos) module.

Each directory includes a specific README file and a makefile.
Please note that the `purelibs` and `vu_module` examples need 
[purelibc](https://github.com/virtualsquare/purelibc) and
[VUOS](https://github.com/virtualsquare/vuos) respectively installed in your system.
The examples `ptrace/ptrace_virt_ssi.c` and `ptrace_seccomp/ptrace_seccomp_virt_ssi.c` require
a (patched) kernel supporting `PTRACE_SET_SYSCALL_INFO`.
