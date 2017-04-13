
#include "fopskit.h"

#ifdef FOPSKIT_CRED_SECURITY

/* give each task a larger cred->security. must be called from stop_machine() */

#define fopskit_remap_cred_security(cred, free) \
	c = cred; \
	old = c->security; \
	if (old) { \
		new = kmemdup(old, sizeof(struct task_security_struct), GFP_KERNEL); \
	} else { \
		new = kmalloc(sizeof(struct task_security_struct), GFP_KERNEL); \
	} \
	if (!new) return -ENOMEM; \
	new->fopskit_flags = 0; \
	c->security = new; \
	if (free && old) kfree(old);

/* use fopskit_init_cred_security() for stop_machine() and hooking of needed symbols */

int fopskit_remap_all_cred_security(void *data) {
	struct task_struct *g, *t, *init = &init_task;
	struct cred *c;
	struct task_security_struct *new = 0;
	void *old;

	/* remap init->cred->security, but don't free the old area */
	fopskit_remap_cred_security((struct cred *)init->real_cred, 0);

	do_each_thread(g, t) {

		if (t->cred != t->real_cred) {
			fopskit_remap_cred_security((struct cred *)t->real_cred, 1);
		}

		if (!new || new != t->cred->security) {
			fopskit_remap_cred_security((struct cred *)t->cred, 1);
		}

	} while_each_thread(g, t);

	return 0;
}

/* return hooks */

static int fopskit_ok(void) { return 0; }
static int fopskit_eperm(void) { return -EPERM; }
static int fopskit_enomem(void) { return -ENOMEM; }

/* user defined way to add code to functions fopskit needs to hook */

struct fops_cred_handler *cred_hook_code;

/* give more memory to the cred->security */

fopskit_hook_handler(security_prepare_creds) {
	struct cred *new = (struct cred *) REGS_ARG1;
	const struct cred *old = (const struct cred *) REGS_ARG2;
	gfp_t gfp = (gfp_t) REGS_ARG3;

	const struct task_security_struct *old_sec;
	struct task_security_struct *sec;

	old_sec = old->security;

	sec = kmemdup(old_sec, sizeof(struct task_security_struct), gfp);

	if (!sec) {
		fopskit_return(fopskit_enomem);
	}

	new->security = sec;

	if (cred_hook_code->security_prepare_creds)
		if (IN_ERR(cred_hook_code->security_prepare_creds(new, old, gfp)))
			fopskit_return(fopskit_eperm);

	fopskit_return(fopskit_ok);
}

fopskit_hook_handler(security_cred_alloc_blank) {
	struct cred *cred = (struct cred *) REGS_ARG1;
	gfp_t gfp = REGS_ARG2;
	struct task_security_struct *sec;

	sec = kzalloc(sizeof(struct task_security_struct), gfp);

	if (!sec) {
		fopskit_return(fopskit_enomem);
	}

	sec->fopskit_flags = 0;
	cred->security = sec;

	if (cred_hook_code->security_cred_alloc_blank)
		if (IN_ERR(cred_hook_code->security_cred_alloc_blank(cred, gfp)))
			fopskit_return(fopskit_eperm);

	fopskit_return(fopskit_ok);
}

/* prevent faults by locking ftrace_enabled */

fopskit_hook_handler(proc_sys_write) {
	char filename[255], *f;
	struct file *file = (struct file *)REGS_ARG1;

	f = d_path(&file->f_path, filename, 255);

	if (!strcmp("/proc/sys/kernel/ftrace_enabled", f))
		fopskit_return(fopskit_eperm);

	if (cred_hook_code->proc_sys_write)
		if (IN_ERR(cred_hook_code->proc_sys_write(file)))
			fopskit_return(fopskit_eperm);
}

/* our use of cred->security requires hooking these functions */

static struct fops_hook fopskit_cred_hooks[] = {
	fops_hook_val(security_prepare_creds),
	fops_hook_val(security_cred_alloc_blank),
	fops_hook_val(proc_sys_write),
};

/* init fopskit use of cred->security */

static struct task_security_struct *init_sec;

int fopskit_init_cred_security(struct fops_cred_handler *h) {
	struct task_struct *init = &init_task;
	int i, ret;

	/* save off init->cred->security */
	init_sec = init->cred->security;

	/* check if memory area of cred->security grew since module compilation */
	if (init->cred->security)
		if (ksize(init->cred->security) >= sizeof(struct task_security_struct))
			return -EFAULT;

	ret = stop_machine(fopskit_remap_all_cred_security, (void *) NULL, NULL);

	if (IN_ERR(ret))
		return ret;

	cred_hook_code = h;

	fopskit_hook_list(fopskit_cred_hooks, 1);

	return 0;

	out_err:
	fopskit_exit();

	return ret;
}

/* goodbye! */

void fopskit_exit(void) {
	struct task_struct *init = &init_task;
	struct cred *ic = (struct cred *) init->cred;
	int i;

	fopskit_unhook_list(fopskit_cred_hooks);

	/* restore original init->cred->security so we can load this module again later */
	ic->security = init_sec;
}

#endif

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

