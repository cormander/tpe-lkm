
#include "tpe.h"

int sysctl = 1;

module_param(sysctl, int, 0);

static int __init tpe_init(void) {

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

static void __exit tpe_exit(void) {

	undo_fopskit_syscalls();
	
	tpe_config_exit();

	printk(PKPRE "removed from kernel\n");

	return;
}

module_init(tpe_init);
module_exit(tpe_exit);

MODULE_AUTHOR("Corey Henderson");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Trusted Path Execution (TPE) Module");
MODULE_VERSION("2.0.0");

