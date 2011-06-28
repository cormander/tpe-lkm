
#include "tpe.h"

/*

This file contains many different ways to locate a symbol's address based on name,
and tries to be the most efficient about it. It uses your System.map file as a last
resort.

*/

#define SYSTEM_MAP_PATH "/boot/System.map-"
#define MAX_LEN 256

// callback for find_symbol_address

static int find_symbol_callback(struct kernsym *sym, const char *name, struct module *mod,
	unsigned long addr) {

	if (sym->found) {
		sym->end_addr = (unsigned long *)addr;
		return 1;
	}

	// this symbol was found. the next callback will be the address of the next symbol
	if (name && sym->name && !strcmp(name, sym->name)) {
		sym->addr = (unsigned long *)addr;
		sym->found = true;
	}

	return 0;
}

// find this symbol

struct kernsym *find_symbol_address(const char *symbol_name) {

	struct kernsym *sym;
	int ret;

	sym = kmalloc(sizeof(sym), GFP_KERNEL);

	if (sym == NULL)
		return -ENOMEM;

	sym->name = (char *)symbol_name;
	sym->found = 0;

	ret = kallsyms_on_each_symbol((void *)find_symbol_callback, sym);

	if (!ret) {
		kfree(sym);
		sym = NULL;
		return -EFAULT;
	}

	sym->size = (unsigned int *)sym->end_addr - (unsigned int *)sym->addr;

	return sym;
}

// RHEL kernels don't compile with CONFIG_PRINTK_TIME. lame.

void up_printk_time(void) {

	struct kernsym *sym;

	sym = find_symbol_address("printk_time");

	if (IS_ERR(sym))
		return;

	if ((int)*sym->addr == 0) {
		*sym->addr = 1;
		printk("Flipped printk_time to 1 because, well, I like it that way!\n");
	}

	kfree(sym);

}

