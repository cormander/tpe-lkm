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

#ifndef CONFIG_SECURITY
#error "This module requires CONFIG_SECURITY to be enabled"
#endif

struct fops_hook {
	char *name;
	void *addr;
	bool found;
	bool hooked;
	struct ftrace_ops *fops;
};

struct fops_cred_handler {
	int (*proc_sys_write)(struct file *);
	int (*security_prepare_creds)(struct cred *, const struct cred *, gfp_t);
	int (*security_cred_alloc_blank)(struct cred *, gfp_t);
};

#define fopskit_return(func) {regs->ip = (unsigned long)func; return;}

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
char *fopskit_sym_str(char *);

#define printfail(msg,func,ret) printk("%s: unable to implement fopskit for %s in %s() at line %d, return code %d\n", msg, func, __FUNCTION__, __LINE__, ret)

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

extern bool fopskit_cred_remapped;
extern size_t cred_sec_size;

int fopskit_init_cred_security(struct fops_cred_handler *);
void fopskit_exit(int);

/* this struct occupies the appended memory area of a task's cred->security
 * change this to your heart's desire; just use the fopskit_cred_security_ptr() macro to access it */

struct fopskit_cred_security {
	unsigned long fopskit_flags;
};

/* roll a pointer forward to the fopskit_cred_security struct area of the given cred->security pointer */
#define fopskit_cred_security_ptr(ptr, tsec) ptr = (struct fopskit_cred_security *) tsec+(cred_sec_size/sizeof(void *))

#endif

