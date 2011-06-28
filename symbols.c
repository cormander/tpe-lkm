
#include "tpe.h"

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

int find_symbol_address(struct kernsym *sym, const char *symbol_name) {

	int ret;

	sym->name = (char *)symbol_name;
	sym->found = 0;

	ret = kallsyms_on_each_symbol((void *)find_symbol_callback, sym);

	if (!ret)
		return -EFAULT;

	sym->size = (unsigned int *)sym->end_addr - (unsigned int *)sym->addr;

	return 0;
}

// RHEL kernels don't compile with CONFIG_PRINTK_TIME. lame.

void up_printk_time(void) {

	int ret;
	struct kernsym *sym;

	sym = kmalloc(sizeof(sym), GFP_KERNEL);

	if (sym == NULL)
		return;

	ret = find_symbol_address(sym, "printk_time");

	if (IS_ERR(ret))
		goto out;

	if ((int)*sym->addr == 0) {
		*sym->addr = 1;
		printk("Flipped printk_time to 1 because, well, I like it that way!\n");
	}

	out:

	kfree(sym);

}

