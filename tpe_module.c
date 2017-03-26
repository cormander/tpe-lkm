
#include "tpe.h"

int sysctl = 1;

module_param(sysctl, int, 0);

int init_tpe(void) {

	int ret = 0;

	if (sysctl) {
		ret = tpe_config_init();

		if (IN_ERR(ret))
			return ret;
	}

	fopskit_syscalls();

	printk(PKPRE "added to kernel\n");

	return ret;
}

static void exit_tpe(void) {

	undo_fopskit_syscalls();
	
	tpe_config_exit();

	printk(PKPRE "removed from kernel\n");

	return;
}

module_init(init_tpe);
module_exit(exit_tpe);

MODULE_AUTHOR("Corey Henderson");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Trusted Path Execution (TPE) Module");
MODULE_VERSION("2.0.0");

