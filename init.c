
#include "tpe.h"

// a wildly elegant piece of module init code

int init_tpe(void) {

	int ret;

	up_printk_time();

	ret = hijack_syscalls();

	if (!IS_ERR(ret))
		printk("TPE added to kernel\n");

	return ret;
}

static void exit_tpe(void) {

	undo_hijack_syscalls();

	printk("TPE removed from kernel\n");

	return;
}

module_init(init_tpe);
module_exit(exit_tpe);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Trusted Path Execution (TPE) Module");

