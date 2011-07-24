
#include "module.h"

static struct kernsym sym_module_alloc;
static struct kernsym sym_module_free;

// locate the module_alloc and module_free symbols

int malloc_init(void) {

	int ret;

	ret = find_symbol_address(&sym_module_alloc, "module_alloc");

	if (IN_ERR(ret))
		return ret;

	ret = find_symbol_address(&sym_module_free, "module_free");

	if (IN_ERR(ret))
		return ret;
	
	return 0;
}

// call to module_alloc

void *malloc(unsigned long size) {
	void *(*run)(unsigned long) = sym_module_alloc.run;
	return run(size);
}

// call to module_free

void malloc_free(void *buf) {
	void (*run)(struct module *, void *) = sym_module_free.run;
	if (buf != NULL)
		run(NULL, buf);
}

