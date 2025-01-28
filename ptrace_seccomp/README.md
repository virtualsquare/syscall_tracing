# PTRACE+SECCOMP

`ptrace` is an ancient system call. It is included in UNIX v6 (1975).
The Linux implentation of `ptrace` evolved during the time.

This directory uses `ptrace` and `seccomp`: the filter program returns `SECCOMP_RET_TRACE`
to notify the system calls to a `ptrace` based tracer.

## PTRACE SECCOMP details

* hypervisor mode.

* (currently) arch dependant. (`PTRACE_SET_SYSCALL_INFO` will permit to write
arch independent code).

* client side thread safe (the hypervisor gets the thread id as the
    return value of wait)

* hypervisor threads: no (clean) way to reroute events to other threads
(vuos' guardian angels has been implemented in a tricky way)

* Using SECCOMP one event is notfied for each system call (while legacy `ptrace`
generated two events per system call).

* designed for debugging

* security: better than `ptrace`: the filter program cannot be removed.
TOCTOU attacks are still possible.

## examples

```
make
```
```
./ptrace_seccomp_virt cat /etc/passwd
./ptrace_seccomp_virt_gsi cat /etc/passwd
./ptrace_seccomp_virt_ssi cat /etc/passwd
```
The output will be the contents of `/etc/hostname`

Note `ptrace_seccomp_virt_ssi` works properly only on patched kernels supporting `PTRACE_SET_SYSCALL_INFO`.

## cleaning

```
make clean
```
