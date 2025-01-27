all: prctl_purelibc_virt prctl_purelibc_virtlib.so

prctl_purelibc_virt: prctl_purelibc_virt.c

prctl_purelibc_virtlib.so: prctl_purelibc_virtlib.c
	$(CC) -fPIC -shared -o prctl_purelibc_virtlib.so prctl_purelibc_virtlib.c

install: all
	cp prctl_purelibc_virtlib.so /tmp

uninstall:
	rm -f  /tmp/prctl_purelibc_virtlib.so

clean:
	rm -f prctl_purelibc_virt prctl_purelibc_virtlib.so
