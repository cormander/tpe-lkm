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
	init.c \
	security.c \
	symbols.c \
	malloc.c \
	hijacks.c

KBUILD_DIR=$(shell sh ./scripts/find_kernel_src.sh)
PWD := $(shell pwd)

all: $(MODULE_NAME).ko

$(MODULE_NAME).ko: $(MODULE_SOURCES)

	$(MAKE) -C $(KBUILD_DIR) M=$(PWD) modules

test: $(MODULE_NAME).ko

	sudo sh ./scripts/test-tpe.sh $(MODULE_NAME)
	
install: $(MODULE_NAME).ko

	sudo /sbin/rmmod $(MODULE_NAME) || :
	sudo /sbin/insmod $(MODULE_NAME).ko

clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(PWD) clean

	rm -f Module*

.PHONY: all clean install test

else
# KBuild part. 
# It is used by the kernel build system to actually build the module.
ccflags-y :=  -I$(src) -I$(src)/$(ARCH_DIR)/include -I$(obj)/$(ARCH_DIR)/lib

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-y := \
	core.o \
	init.o \
	security.o \
	symbols.o \
	malloc.o \
	hijacks.o \
	$(ARCH_DIR)/lib/inat.o \
	$(ARCH_DIR)/lib/insn.o

$(obj)/$(ARCH_DIR)/lib/inat.o: $(obj)/$(ARCH_DIR)/lib/$(INAT_TABLES_FILE) $(src)/$(ARCH_DIR)/lib/inat.c

$(obj)/$(ARCH_DIR)/lib/$(INAT_TABLES_FILE): $(src)/$(ARCH_DIR)/lib/x86-opcode-map.txt 
	LC_ALL=C awk -f $(src)/$(ARCH_DIR)/tools/gen-insn-attr-x86.awk $< > $@

endif
