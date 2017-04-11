
#include "fopskit.h"

/* callback for fopskit_find_sym_addr */

static int fopskit_find_sym_callback(struct fops_hook *hook, const char *name, struct module *mod,
	unsigned long addr) {

	if (hook->found)
		return 1;

	/* this symbol was found. the next callback will be the address of the next symbol */
	if (name && hook->name && !strcmp(name, hook->name)) {
		hook->addr = (unsigned long *)addr;
		hook->found = true;
	}

	return 0;
}

/* find this symbol */

static int fopskit_find_sym_addr(struct fops_hook *hook) {

	hook->found = false;

	if (!kallsyms_on_each_symbol((void *)fopskit_find_sym_callback, hook))
		return -EFAULT;

	return 0;
}

/* hook this symbol */

int fopskit_sym_hook(struct fops_hook *hook) {
	int ret;

	ret = fopskit_find_sym_addr(hook);

	if (IN_ERR(ret))
		return ret;

	preempt_disable_notrace();

	ret = ftrace_set_filter_ip(hook->fops, (unsigned long) hook->addr, 0, 0);

	if (IN_ERR(ret))
		return ret;

	ret = register_ftrace_function(hook->fops);

	if (IN_ERR(ret))
		return ret;

	hook->hooked = true;

	preempt_enable_notrace();

	return 0;
}

/* unhook this symbol */

int fopskit_sym_unhook(struct fops_hook *hook) {
	int ret;

	if (hook->hooked) {

		preempt_disable_notrace();

		ret = unregister_ftrace_function(hook->fops);

		if (IN_ERR(ret))
			return ret;

		ret = ftrace_set_filter_ip(hook->fops, (unsigned long) hook->addr, 1, 0);

		if (IN_ERR(ret))
			return ret;

		hook->hooked = false;

		preempt_enable_notrace();
	}

	return 0;
}

/* find int value of this symbol */

int fopskit_sym_int(char *name) {
	static struct ftrace_ops fops_int;
	struct fops_hook hook_int = {name, NULL, false, false, &fops_int};
	int ret;

	ret = fopskit_find_sym_addr(&hook_int);

	if (IN_ERR(ret))
		return -EFAULT;

	return *((int *)hook_int.addr);
}

