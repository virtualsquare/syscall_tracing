all: nopasswd.so nopasswdf.so

nopasswd.so: nopasswd.c
	$(CC) -fPIC -shared -o nopasswd.so nopasswd.c

nopasswdf.so: nopasswdf.c
	$(CC) -fPIC -shared -o nopasswdf.so nopasswdf.c

install: all
	mkdir -p ~/.vu/modules
	cp nopasswd.so nopasswdf.so ~/.vu/modules

uninstall:
	rm -f  ~/.vu/modules/nopasswd.so
	rm -f  ~/.vu/modules/nopasswdf.so
	rmdir --ignore-fail-on-non-empty ~/.vu/modules ~/.vu

clean:
	rm -f nopasswd.so nopasswdf.so
