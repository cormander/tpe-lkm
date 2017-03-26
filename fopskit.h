#ifndef FOPSKIT_H_INCLUDED
#define FOPSKIT_H_INCLUDED

#include <linux/ftrace.h>

#ifdef CONFIG_X86_64
#define REGS_ARG1(r) r->di
#define REGS_ARG2(r) r->si
#define REGS_ARG3(r) r->dx
#else
#error "Arch not currently supported."
#endif

struct kernsym {
	void *addr;
	char *name;
	bool found;
	bool ftraced;
};

struct symhook {
	char *name;
	struct kernsym *sym;
	struct ftrace_ops *fops;
};

#define symhook_val(val) \
	{#val, &sym_##val, &fops_##val}

#define fopskit_trace_handler(val) \
	static void notrace fopskit_##val(unsigned long, unsigned long, \
		struct ftrace_ops *, struct pt_regs *); \
	struct kernsym sym_##val; \
	static struct ftrace_ops fops_##val __read_mostly = { \
		.func = fopskit_##val, \
		.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY, \
	}; \
	static void notrace fopskit_##val(unsigned long ip, unsigned long parent_ip, \
		struct ftrace_ops *fops, struct pt_regs *regs)

#define IN_ERR(x) (x < 0)

#endif
