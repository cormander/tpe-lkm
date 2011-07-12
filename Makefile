MODULE_NAME := tpe

# This subdirectory contains necessary files for both x86 and x86-64.
ARCH_DIR := arch/x86

EXTRA_CFLAGS += -I$(src) -I$(src)/$(ARCH_DIR)/include -I$(obj)/$(ARCH_DIR)/lib

# This auxiliary file will be generated during the build (x86 instruction 
# tables as C code).
INAT_TABLES_FILE := inat-tables.h

ifeq ($(KERNELRELEASE),)
# 'Out-of-kernel' part

MODULE_SOURCES := \
	core.c \
	module.c \
	security.c \
	symbols.c \
	malloc.c \
	sysctl.c \
	hijacks.c

TESTS := tests/mmap-mprotect-test

KBUILD_DIR=$(shell sh ./scripts/find_kernel_src.sh)
PWD := $(shell pwd)

all: $(MODULE_NAME).ko

$(MODULE_NAME).ko: $(MODULE_SOURCES)

	$(MAKE) -C $(KBUILD_DIR) M=$(PWD) modules

test: $(MODULE_NAME).ko $(TESTS)

	sudo sh ./scripts/run_tests.sh $(MODULE_NAME)
	
install_files: $(MODULE_NAME).ko

	mkdir -p $(DESTDIR)/lib/modules/generic
	install -m 644 conf/modules.dep $(DESTDIR)/lib/modules/generic
	install -m 644 conf/tpe.modprobe.conf $(DESTDIR)/etc/modprobe.d/tpe.conf
	[ -d $(DESTDIR)/etc/sysconfig/modules ] && install -m 755 conf/tpe.sysconfig $(DESTDIR)/etc/sysconfig/modules/tpe.modules || :
	install -m 755 $(MODULE_NAME).ko $(DESTDIR)/lib/modules/generic

install: install_files

	rmmod $(MODULE_NAME) || :
	modprobe $(MODULE_NAME)

rpm:

	sh ./scripts/mk_rpm.sh

clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(PWD) clean

	rm -f Module* $(TESTS)

.PHONY: all clean install install_files test rpm

else
# KBuild part. 
# It is used by the kernel build system to actually build the module.
ccflags-y :=  -I$(src) -I$(src)/$(ARCH_DIR)/include -I$(obj)/$(ARCH_DIR)/lib

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-y := \
	core.o \
	module.o \
	security.o \
	symbols.o \
	malloc.o \
	sysctl.o \
	hijacks.o \
	$(ARCH_DIR)/lib/inat.o \
	$(ARCH_DIR)/lib/insn.o

$(obj)/$(ARCH_DIR)/lib/inat.o: $(obj)/$(ARCH_DIR)/lib/$(INAT_TABLES_FILE) $(src)/$(ARCH_DIR)/lib/inat.c

$(obj)/$(ARCH_DIR)/lib/$(INAT_TABLES_FILE): $(src)/$(ARCH_DIR)/lib/x86-opcode-map.txt 
	LC_ALL=C awk -f $(src)/$(ARCH_DIR)/tools/gen-insn-attr-x86.awk $< > $@

endif
