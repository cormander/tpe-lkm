
#include "tpe.h"

void *(*module_alloc_func)(unsigned long) = NULL;
void (*module_free_func)(struct module *, void *) = NULL;

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
	
	module_alloc_func = (void *(*)(unsigned long))sym_module_alloc.addr;
	module_free_func = (void (*)(struct module *, void *))sym_module_free.addr;

	if (module_alloc_func == NULL) {
		printk(KERN_ERR "[tpe] "
			"Unable to find \"module_alloc\" function\n");
		return -EFAULT;
	}
	
	if (module_free_func == NULL) {
		printk(KERN_ERR "[tpe] "
			"Unable to find \"module_free\" function\n");
		return -EFAULT;
	}
		
	return 0;
}

// "forget" about it

void malloc_clean(void) {
	module_alloc_func = NULL;
	module_free_func = NULL;
}

// call to module_alloc

void *malloc(unsigned long size) {
	BUG_ON(module_alloc_func == NULL);
	return module_alloc_func(size);
}

// call to module_free

void malloc_free(void *buf) {
	BUG_ON(module_free_func == NULL);
	if (buf != NULL)
		module_free_func(NULL, buf);
}

