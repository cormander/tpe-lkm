
#include <linux/module.h>
#include <asm/uaccess.h>
#include "../../fopskit.h"

int uname_eperm(void) { return -EACCES; }

fopskit_hook_handler(sys_newuname) {
	char *name = (char *)REGS_ARG1;
	char str[] = "mighty fine shindig";

	if (!capable(CAP_SYS_ADMIN)) {
		copy_to_user(name, str, sizeof(str));
		fopskit_return(uname_eperm);
	}
}

static struct fops_hook uname_hooks[] = {
	fops_hook_val(sys_newuname),
};

static int __init uname_init(void) {
	int i, ret;
	fopskit_hook_list(uname_hooks, 1);
	return 0;
	out_err:
	return ret;
}

static void __exit uname_exit(void) {
	int i;
	fopskit_unhook_list(uname_hooks);
}

module_init(uname_init);
module_exit(uname_exit);
MODULE_LICENSE("GPL");

