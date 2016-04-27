# $Id: Makefile 67 2006-12-11 06:39:55Z dlg@itee $

all: mfii
clean:
	rm mfii.o mfii

mfii: mfii.o
	/usr/ccs/bin/ld -r -o mfii mfii.o

CFLAGS += -I${HOME}/illumos-joyent/usr/src/uts/intel
CFLAGS += -I${HOME}/illumos-joyent/usr/src/uts/common
CFLAGS += -Wall
CFLAGS += -Wno-unknown-pragmas
CFLAGS += -Wno-missing-braces
CFLAGS += -D_KERNEL -m64 -mcmodel=kernel -mno-red-zone -ffreestanding -nodefaultlibs

mfii.o: mfii.c mfiireg.h
