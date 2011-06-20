ifneq ($(KERNELRELEASE),)
	obj-m := tpe.o
	tpe-objs := addrs.o execve.o tpe_core.o
else

KDIR=$(shell sh ./scripts/find_kernel_src.sh)

all:

	perl ./scripts/gen_addrs.pl > addrs.c

	make -C $(KDIR) M=$(PWD) modules

test: all

	sudo sh ./scripts/test-tpe.sh

install: all

	sudo /sbin/rmmod tpe || :
	sudo /sbin/insmod tpe.ko

clean:

	make -C $(KDIR) M=$(PWD) clean
	rm -f addrs.c addr_template.c

endif
