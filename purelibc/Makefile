LDLIBS = -lpurelibc

all: puretest_virt xchange.so resolvconfx.so

puretest_virt: puretest_virt.c

xchange.so: xchange.c
	$(CC) -fPIC -shared -o xchange.so xchange.c $(LDLIBS)

resolvconfx.so: resolvconfx.c
	$(CC) -fPIC -shared -o resolvconfx.so resolvconfx.c $(LDLIBS)

install: all
	cp xchange.so resolvconfx.so /tmp

uninstall:
	rm -f /tmp/xchange.so
	rm -f /tmp/resolvconfx.so

clean:
	rm -f puretest_virt xchange.so resolvconfx.so
