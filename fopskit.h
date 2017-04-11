#ifndef FOPSKIT_H_INCLUDED
#define FOPSKIT_H_INCLUDED

#include <linux/ftrace.h>
#include <linux/stop_machine.h>
#include <linux/slab.h>

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

#define fopskit_return(func) regs->ip = (unsigned long)func; return;

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

int fopskit_remap_all_cred_security(void *);
int fopskit_sym_hook(struct fops_hook *);
int fopskit_sym_unhook(struct fops_hook *);
int fopskit_sym_int(char *);

#define fopskit_init_cred_security() stop_machine(fopskit_remap_all_cred_security, (void *) NULL, NULL);

#define printfail(msg,func,ret) printk(PKPRE "%s: unable to implement fopskit for %s in %s() at line %d, return code %d\n", msg, func, __FUNCTION__, __LINE__, ret)

#define fopskit_hook_list(hooks, val) \
	for (i = 0; i < ARRAY_SIZE(hooks); i++) { \
		ret = fopskit_sym_hook(&hooks[i]); \
		if (IN_ERR(ret)) { \
			if (val) { \
				printfail("fatal", hooks[i].name, ret); \
				goto out_err; \
			} else { \
				printfail("warning", hooks[i].name, ret); \
			} \
		} \
	}

#define fopskit_unhook_list(hooks) \
	for (i = 0; i < ARRAY_SIZE(hooks); i++) { \
		fopskit_sym_unhook(&hooks[i]); \
	}

/* TODO: handle the other LSM structs here */

struct task_security_struct {
#ifdef CONFIG_SECURITY_SELINUX
/* selinux */
        u32 osid;               /* SID prior to last execve */
        u32 sid;                /* current SID */
        u32 exec_sid;           /* exec SID */
        u32 create_sid;         /* fscreate SID */
        u32 keycreate_sid;      /* keycreate SID */
        u32 sockcreate_sid;     /* fscreate SID */
        u32 buffer1;            /* buffers, incase this ever grows */
        u32 buffer2;
        u32 buffer3;
        u32 buffer4;
        u32 buffer5;
        u32 buffer6;
        u32 buffer7;
#else
#error "Selected CONFIG_SECURITY not currently supported."
#endif
        unsigned long fopskit_flags;
};

#endif

