
#include "module.h"

// callback for find_symbol_address

static int find_symbol_callback(struct kernsym *sym, const char *name, struct module *mod,
	unsigned long addr) {

	if (sym->found) {
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

	return 0;
}

static int find_address_callback(struct kernsym *sym, const char *name, struct module *mod,
	unsigned long addr) {

	if (sym->found) {
		return 1;
	}

	// this address was found. the next callback will be the address of the next symbol
	if (addr && (unsigned long) sym->addr == addr) {
		sym->name = malloc(strlen(name)+1);
		strncpy(sym->name, name, strlen(name)+1);
		sym->name_alloc = true;
		sym->found = true;
	}

	return 0;
}

int find_address_symbol(struct kernsym *sym, unsigned long addr) {

	int ret;

	sym->found = 0;
	sym->addr = (unsigned long *)addr;

	ret = kallsyms_on_each_symbol((void *)find_address_callback, sym);

	if (!ret)
		return -EFAULT;

	return 0;
}

