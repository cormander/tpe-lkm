MODULE_NAME := tpe

EXTRA_CFLAGS += -I$(src)

ifeq ($(KERNELRELEASE),)
# 'Out-of-kernel' part

MODULE_SOURCES := \
	core.c \
	module.c \
	security.c \
	symbols.c \
	kernfunc.c \
	sysctl.c \
	hijacks.c

TESTS := tests/mmap-mprotect-test tests/sysctl-restrict_setuid

KBUILD_DIR=$(shell sh ./scripts/find_kernel_src.sh)
UNAME=$(shell uname -r)
PWD := $(shell pwd)

all: $(MODULE_NAME).ko

$(MODULE_NAME).ko: $(MODULE_SOURCES)

	$(MAKE) -C $(KBUILD_DIR) M=$(PWD) modules

test: $(MODULE_NAME).ko $(TESTS)

	sudo sh ./scripts/run_tests.sh $(MODULE_NAME)
	
install_files: $(MODULE_NAME).ko

	mkdir -p $(DESTDIR)/lib/modules/$(UNAME)/extra/tpe
	mkdir -p $(DESTDIR)/etc/modprobe.d
	mkdir -p $(DESTDIR)/etc/sysctl.d
	install -m 644 conf/tpe.modprobe.conf $(DESTDIR)/etc/modprobe.d/tpe.conf
	install -m 644 conf/tpe.sysctl $(DESTDIR)/etc/sysctl.d/tpe.conf
	[ -d $(DESTDIR)/etc/sysconfig/modules ] && install -m 755 conf/tpe.sysconfig $(DESTDIR)/etc/sysconfig/modules/tpe.modules || :
	install -m 755 $(MODULE_NAME).ko $(DESTDIR)/lib/modules/$(UNAME)/extra/tpe/
	/sbin/depmod

install: install_files

	rmmod $(MODULE_NAME) || :
	modprobe $(MODULE_NAME)

tarball:

	sh ./scripts/make_tarball.sh

clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(PWD) clean

	rm -f Module* $(TESTS) tests.out

.PHONY: all clean install install_files test tarball

else
# KBuild part. 
# It is used by the kernel build system to actually build the module.
ccflags-y :=  -I$(src)

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-y := \
	core.o \
	module.o \
	security.o \
	symbols.o \
	kernfunc.o \
	sysctl.o \
	hijacks.o

endif
