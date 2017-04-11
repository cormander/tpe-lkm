#ifndef FOPSKIT_H_INCLUDED
#define FOPSKIT_H_INCLUDED

#include <linux/ftrace.h>

#ifdef CONFIG_X86_64
#define REGS_ARG1 regs->di
#define REGS_ARG2 regs->si
#define REGS_ARG3 regs->dx
#else
#error "Arch not currently supported."
#endif

struct fops_hook {
	char *name;
	void *addr;
	bool found;
	bool hooked;
	struct ftrace_ops *fops;
};

#define fopskit_return(func) regs->ip = (unsigned long)func;

#define fops_hook_val(val) \
	{#val, NULL, false, false, &fops_##val}

#define fopskit_hook_handler(val) \
	static void notrace fopskit_##val(unsigned long, unsigned long, \
		struct ftrace_ops *, struct pt_regs *); \
	static struct ftrace_ops fops_##val __read_mostly = { \
		.func = fopskit_##val, \
		.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY, \
	}; \
	static void notrace fopskit_##val(unsigned long ip, unsigned long parent_ip, \
		struct ftrace_ops *fops, struct pt_regs *regs)

#define IN_ERR(x) (x < 0)

int fopskit_sym_hook(struct fops_hook *);
int fopskit_sym_unhook(struct fops_hook *);
int fopskit_sym_int(char *);

#endif
