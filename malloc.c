
#include "tpe.h"

static struct kernsym sym_module_alloc;
static struct kernsym sym_module_free;

// locate the module_alloc and module_free symbols

int malloc_init(void) {

	int ret;

	ret = find_symbol_address(&sym_module_alloc, "module_alloc");

	if (IS_ERR(ret))
		return ret;

	ret = find_symbol_address(&sym_module_free, "module_free");

	if (IS_ERR(ret))
		return ret;
	
	return 0;
}

// call to module_alloc

void *malloc(unsigned long size) {
	return sym_module_alloc.run(size);
}

// call to module_free

void malloc_free(void *buf) {
	if (buf != NULL)
		sym_module_free.run(NULL, buf);
}

