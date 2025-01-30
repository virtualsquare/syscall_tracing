# SECCOMP-UNOTIFY

Seccomp-unotify haas been designed for alien O.S. emulation (e.g. wine or limbo/XNU).

This example has been inspired by the code published in the man page.

However,the example code in the man page uses sendmsg/recvmsg and ancillary messages
to transfer the notify fd from the tracee to the tracer/hypervisor.
In this way it is not possible to capture *all* the syscalls
(at least sendmsg/recvmsg cannot be captured).
In order to capture all the system calls it needs a way to send the
notify fd without using any system call on the tracee process.
We applied a tricky solution:
use a shared memory to send to the hypervisor le value of `notify_fd`
of the tracee and
use `pidfd_getfd` (on the hypervisor side) to get a 'dup' of the tracee's
`notify_fd`.


## SECCOMP-UNOTIFY details

* hypervisor mode (forwarding the notify fd to the hypervisor process).

* syscall event notification via: pollable file descriptor + ioctl

* arch independent

* syscalls run at hypervisor side, `SECCOMP_IOCTL_NOTIF_SEND` returns result/errno.
seccomp-unotify is able to run or skip the kernel syscall. It is not
possible to modify the syscall's args.

* it is possible to create a remote dup of a file descriptor of the hypervisor
using  `SECCOMP_IOCTL_NOTIF_ADDFD` to the tracee process.

*  new threads/processes inherit the bpf program and are traced by the
hypervisor.

* parallel performance: no way to "move" the new process/thread to a different fd.


## example
```
make
```
```
./seccomp_unotify_virt cat /etc/passwd
```
The output will be the contents of `/etc/hostname`

### cleaning
```
make clean
```
