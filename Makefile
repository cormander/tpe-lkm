ifneq ($(KERNELRELEASE),)
	obj-m += tpe.o
else

KDIR=$(shell sh ./scripts/find_kernel_src.sh)

all:

	sh -xe ./scripts/insert_addr.sh tpe_template.c tpe.c

	make -C $(KDIR) M=$(PWD) modules

install: all

	sudo rmmod tpe || :
	sudo insmod tpe.ko

clean:

	make -C $(KDIR) M=$(PWD) clean
	rm -f tpe.c

endif
