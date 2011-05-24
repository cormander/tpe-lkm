ifneq ($(KERNELRELEASE),)
	obj-m += tpe.o
else

KDIR=$(shell sh ./scripts/find_kernel_src.sh)

all:

	sh -xe ./scripts/insert_addr.sh tpe_template.c tpe.c

	make -C $(KDIR) M=$(PWD) modules

test: all

	sudo sh ./scripts/test-tpe.sh

install: all

	sudo /sbin/rmmod tpe || :
	sudo /sbin/insmod tpe.ko

clean:

	make -C $(KDIR) M=$(PWD) clean
	rm -f tpe.c

endif
