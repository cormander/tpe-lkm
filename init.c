
#include "tpe.h"

// a wildly elegant piece of module init code

int init_tpe(void) {

	int ret;

	ret = malloc_init();

	if (IS_ERR(ret))
		return ret;

	ret = hijack_syscalls();

	if (!IS_ERR(ret))
		printk("[tpe] protection added to kernel\n");

	return ret;
}

static void exit_tpe(void) {

	undo_hijack_syscalls();
	
	malloc_clean();

	printk("[tpe] protection removed from kernel\n");

	return;
}

module_init(init_tpe);
module_exit(exit_tpe);

MODULE_AUTHOR("Corey Henderson");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Trusted Path Execution (TPE) Module");

