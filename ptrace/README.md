# PTRACE

`ptrace` is an ancient system call. It is included in UNIX v6 (1975).
The Linux implentation of `ptrace` evolved during the time.

A *tracer* process can be informed of (trace) specific events of a *tracee* process.
The *tracer* can also modify data in the *tracee*'s memory and registers.

Notification of this event is delivered via `wait(2)`.

The evolution of `ptrace` includes new tags to provide the *tracer* with more detailed
events and new methods to access *tracee* data.

As for CPU registers:

* initially `ptrace` supported two tags `PTRACE_PEEKUSER` and `PTRACE_POKEUSER`. These tags transfers one register at a time. This approach is time consuming and architecture dependent.

* new tags `PTRACE_GETREGS`/`PTRACE_SETREGS` and then `PTRACE_GETREGSET`/`PTRACE_SETREGSET`
provided a more effective way to read/write sets of registers as a whole. The usage of these tags to trace system call is still arch dependent.

* more recently `PTRACE_GET_SYSCALL_INFO` implemented an arch independent way to *read*
the syscall related information. The tool `strace` has benefited greatly from this new feature.
Unfortunately `PTRACE_GET_SYSCALL_INFO` was released incomplete of its complementary
`PTRACE_SET_SYSCALL_INFO` companion.

* We proposed to fill this gap in 2022 and 2024. Dmitry V. Levin is actively working in these
days to add this feature.

As for *tracee*'s memory access:

* initially the tags `PTRACE_PEEKDATA`/`PTRACE_POKEDATA` prmitted to transfer one memory word
at a time.

* more recently two specific system calls were added `process_vm_readv`/`process_vm_writev`.

* the pseudo-file `/proc/..pid../mem` provides another way to read/write the *tracee*'s
memory.

## PTRACE details

* hypervisor mode.

* syscall event notification via: tracee process state change. i.e. via wait(2).

* (currently) arch dependant. (`PTRACE_SET_SYSCALL_INFO` will permit to write
arch independent code).

* client side thread safe (the hypervisor gets the thread id as the
    return value of wait)

* hypervisor threads: no (clean) way to reroute events to other threads
(vuos' guardian angels has been implemented in a tricky way)

* two events for each system call (SYSCALL IN/OUT)
	(the tag `PTRACE_SYSEMU` was created for user-mode-linux.
	 the kernel does not receive the system call and it skips the SYSCALL IN
	 event)

* designed for debugging

* security: hard to enforce

## examples

```
make
```
```
./ptrace_virt cat /etc/passwd
./ptrace_virt_gsi cat /etc/passwd
./ptrace_virt_ssi cat /etc/passwd
```
The output will be the contents of `/etc/hostname`

Note `ptrace_virt_ssi` works properly only on patched kernels supporting `PTRACE_SET_SYSCALL_INFO`.

## cleaning

```
make clean
```
