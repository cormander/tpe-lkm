
#include "module.h"

// a wildly elegant piece of module init code

int init_tpe(void) {

	int ret;

	ret = tpe_config_init();

	if (IN_ERR(ret))
		return ret;

	ret = malloc_init();

	if (IN_ERR(ret))
		return ret;

	hijack_syscalls();

	printk(PKPRE "added to kernel\n");

	return ret;
}

static void exit_tpe(void) {

	undo_hijack_syscalls();
	
	printk(PKPRE "removed from kernel\n");

	tpe_config_exit();

	return;
}

module_init(init_tpe);
module_exit(exit_tpe);

MODULE_AUTHOR("Corey Henderson");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Trusted Path Execution (TPE) Module");

