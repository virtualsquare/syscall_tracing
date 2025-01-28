# VUOS `vu_module`

This example needs [VUOS](https://github.com/virtualsquare/vuos).

VUOS is a Virtual Operating System implemented at user space. Currently it implements about 150 Linux-compatible system calls providing support for a wide range of applications. Each process or even each thread in VUOS can see a different execution environment: file system contents, networking, devices, user ids etc. The main idea behind VUOS is that it is possible to give processes their own "view" using partial virtual machines.

VUOS 

## `vu_module` details

* hypervisor mode

* arch independent

* modular

* parallel tracing

## examples

```
make
make install
```
Run a vuos session and test:

```
umvu bash
vu_insmod nopasswd
cat /etc/passwd
exit
```
The command `cat` shows the contents of `/etc/hostname.

### cleaning
```
make uninstall
make clean
```
