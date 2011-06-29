
#include "tpe.h"

// for debugging

void symbol_info(struct kernsym *sym) {

	printk("[tpe] name => %s, addr => %lx, end_addr => %lx, size => %d, new_addr => %lx, new_size => %d, found => %d\n",
		sym->name,
		sym->addr,
		sym->end_addr,
		sym->size,
		sym->new_addr,
		sym->new_size,
		sym->found);
}

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

	sym->size = sym->end_addr - sym->addr;
	sym->new_size = sym->size;

	return 0;
}

