
#include "fopskit.h"

/* callback for fopskit_find_sym_addr */

static int fopskit_find_sym_callback(struct kernsym *sym, const char *name, struct module *mod,
	unsigned long addr) {

	if (sym->found) {
		return 1;
	}

	/* this symbol was found. the next callback will be the address of the next symbol */
	if (name && sym->name && !strcmp(name, sym->name)) {
		sym->addr = (unsigned long *)addr;
		sym->found = true;
	}

	return 0;
}

/* find this symbol */

int fopskit_find_sym_addr(struct kernsym *sym, const char *symbol_name) {

	int ret;

	sym->name = (char *)symbol_name;
	sym->found = 0;

	ret = kallsyms_on_each_symbol((void *)fopskit_find_sym_callback, sym);

	if (!ret)
		return -EFAULT;

	return 0;
}

/* hook this symbol */

int fopskit_sym_hook(struct symhook *hook) {
	int ret;

	ret = fopskit_find_sym_addr(hook->sym, hook->name);

	if (IN_ERR(ret))
		return ret;

	preempt_disable_notrace();

	ret = ftrace_set_filter_ip(hook->fops, (unsigned long) hook->sym->addr, 0, 0);

	if (IN_ERR(ret))
		return ret;

	ret = register_ftrace_function(hook->fops);

	if (IN_ERR(ret))
		return ret;

	hook->sym->ftraced = true;

	preempt_enable_notrace();

	return 0;
}

/* unhook this symbol */

int fopskit_sym_unhook(struct symhook *hook) {
	int ret;

	if (hook->sym->ftraced) {

		preempt_disable_notrace();

		ret = unregister_ftrace_function(hook->fops);

		if (IN_ERR(ret))
			return ret;

		ret = ftrace_set_filter_ip(hook->fops, (unsigned long) hook->sym->addr, 1, 0);

		if (IN_ERR(ret))
			return ret;

		hook->sym->ftraced = false;

		preempt_enable_notrace();
	}

	return 0;
}

