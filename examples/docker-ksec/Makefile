MODULE_NAME := docker-ksec

EXTRA_CFLAGS += -I$(src)

ifeq ($(KERNELRELEASE),)
# 'Out-of-kernel' part

MODULE_SOURCES := \
	../../fopskit.c \
	ksec_module.c

KBUILD_DIR=$(shell sh ../../scripts/find_kernel_src.sh)
UNAME=$(shell uname -r)
PWD := $(shell pwd)

all: $(MODULE_NAME).ko

$(MODULE_NAME).ko: $(MODULE_SOURCES)

	$(MAKE) -C $(KBUILD_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(PWD) clean

	rm -f Module*

.PHONY: all clean

else
# KBuild part. 
# It is used by the kernel build system to actually build the module.
ccflags-y := -I$(src)

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-y := \
	../../fopskit.o \
	ksec_module.o

endif
