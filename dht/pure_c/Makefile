CC = /usr/bin/clang
CFLAGS = -g

run: build
	./a.out

debub: build
	gdb -ex run ./a.out

build:
	$(CC) $(CFLAGS) *.c -luv -DLOGLEVEL=1
