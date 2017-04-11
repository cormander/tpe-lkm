
#include "tpe.h"
#include "fopskit.h"

/* regs->ip gets set to here when we want to deny execution */

static int tpe_donotexec(void) {

	/* if not a root process and kill is enabled, kill it */
	if (tpe_kill && get_task_uid(current)) {
		(void)send_sig_info(SIGKILL, NULL, current);
		/* only kill the parent if it isn't root */
		if (get_task_uid(get_task_parent(current)))
			(void)send_sig_info(SIGKILL, NULL, get_task_parent(current));
	}

	return -EACCES;
}

/* other return hooks */

static int tpe_ok(void) { return 0; }
static int tpe_enomem(void) { return -ENOMEM; }

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
		regs->ip = (unsigned long)tpe_enomem;
	} else {
		new->security = sec;
		regs->ip = (unsigned long)tpe_ok;
	}

}

fopskit_hook_handler(security_cred_alloc_blank) {
	struct cred *cred = (struct cred *) REGS_ARG1;
	gfp_t gfp = REGS_ARG2;
	struct task_security_struct *sec;

	sec = kzalloc(sizeof(struct task_security_struct), gfp);
	
	if (!sec) {
		regs->ip = (unsigned long)tpe_enomem;
	} else {
		sec->soften_mmap = 0;
		cred->security = sec;
		regs->ip = (unsigned long)tpe_ok;
	}

}

#define TPE_NOEXEC if (!tpe_softmode) regs->ip = (unsigned long)tpe_donotexec
#define TPE_NOEXEC_LOG(val) if (tpe_log_denied_action(current->mm->exe_file, val, "tpe_extras")) TPE_NOEXEC;

/* mmap */

fopskit_hook_handler(security_mmap_file) {
	struct file *file = (struct file *)REGS_ARG1;
	struct task_security_struct *sec = current->cred->security;

	if (file && (REGS_ARG2 & PROT_EXEC))
		if (!sec->soften_mmap && tpe_allow_file(file, "mmap"))
			TPE_NOEXEC;
}

/* mprotect */

fopskit_hook_handler(security_file_mprotect) {
	struct vm_area_struct *vma = (struct vm_area_struct *)REGS_ARG1;

	if (vma->vm_file && (REGS_ARG2 & PROT_EXEC))
		if (tpe_allow_file(vma->vm_file, "mprotect"))
			TPE_NOEXEC;
}

/* execve */

fopskit_hook_handler(security_bprm_check) {
	struct linux_binprm *bprm = (struct linux_binprm *)REGS_ARG1;
	struct task_security_struct *sec;

	if (bprm->file) {
		/* load xattr flag for soften_mmap if it's there */
		if (tpe_file_getfattr(bprm->file, "mmap")) {
			sec = bprm->cred->security;
			sec->soften_mmap = 1;
		}

		if (tpe_allow_file(bprm->file, "exec"))
			TPE_NOEXEC;
	}
}

/* sysctl locks */

fopskit_hook_handler(proc_sys_write) {
	char filename[MAX_FILE_LEN], *f;
	struct file *file = (struct file *)REGS_ARG1;

	f = tpe_d_path(file, filename, MAX_FILE_LEN);

	if (!strcmp("/proc/sys/kernel/ftrace_enabled", f) ||
		(tpe_lock && !strncmp("/proc/sys/tpe", f, 13)))
		TPE_NOEXEC;
}

/* pid_revalidate */

fopskit_hook_handler(pid_revalidate) {
	struct dentry *dentry = (struct dentry *)REGS_ARG1;

	if (tpe_ps && !capable(CAP_SYS_ADMIN) &&
		dentry->d_inode && __kuid_val(dentry->d_inode->i_uid) != get_task_uid(current) &&
		dentry->d_parent->d_inode && __kuid_val(dentry->d_parent->d_inode->i_uid) != get_task_uid(current) &&
		(!tpe_ps_gid || (tpe_ps_gid && !in_group_p(KGIDT_INIT(tpe_ps_gid)))))
		TPE_NOEXEC;
}

/* security_task_fix_setuid */

fopskit_hook_handler(security_task_fix_setuid) {
	struct cred *new = (struct cred *)REGS_ARG1;
	struct cred *old = (struct cred *)REGS_ARG2;

	if (tpe_restrict_setuid && !__kuid_val(new->uid) && !UID_IS_TRUSTED(__kuid_val(old->uid)))
		TPE_NOEXEC_LOG("setuid");
}

/* lsmod */

fopskit_hook_handler(m_show) {
	if (tpe_lsmod && !capable(CAP_SYS_MODULE))
		TPE_NOEXEC_LOG("lsmod");
}

/* kallsyms_open */

fopskit_hook_handler(kallsyms_open) {
	if (tpe_proc_kallsyms && (tpe_paranoid || !capable(CAP_SYS_ADMIN)))
		TPE_NOEXEC_LOG("kallsyms");
}

/* security_ptrace_access_check */

fopskit_hook_handler(security_ptrace_access_check) {
	struct task_struct *t, *task = (struct task_struct *)REGS_ARG1;

	if (tpe_harden_ptrace && (REGS_ARG2 & PTRACE_MODE_ATTACH)) {
		t = task;

		while (task_pid_nr(t) > 0) {
			if (t == current)
				break;
			t = t->real_parent;
		}

		if (task_pid_nr(t) == 0 && !UID_IS_TRUSTED(get_task_uid(current)))
			TPE_NOEXEC_LOG("ptrace");
	}
}

/* sys_newuname */

fopskit_hook_handler(sys_newuname) {
	if (tpe_hide_uname && !UID_IS_TRUSTED(get_task_uid(current)))
		TPE_NOEXEC_LOG("uname");
}

fopskit_hook_handler(proc_sys_read) {
	char filename[MAX_FILE_LEN], *f;
	struct file *file;

	if (tpe_hide_uname) {
		file = (struct file *)REGS_ARG1;
		f = tpe_d_path(file, filename, MAX_FILE_LEN);

		if (!strcmp("/proc/sys/kernel/osrelease", f))
			TPE_NOEXEC_LOG("uname");
	}
}

/* each call to fopskit_hook_handler() needs a corresponding entry here */

static struct fops_hook tpe_hooks[] = {
	fops_hook_val(security_prepare_creds),
	fops_hook_val(security_cred_alloc_blank),
	fops_hook_val(security_mmap_file),
	fops_hook_val(security_file_mprotect),
	fops_hook_val(security_bprm_check),
	fops_hook_val(proc_sys_write),
};

static struct fops_hook tpe_hooks_extras[] = {
	fops_hook_val(security_task_fix_setuid),
	fops_hook_val(security_ptrace_access_check),
	fops_hook_val(pid_revalidate),
	fops_hook_val(m_show),
	fops_hook_val(kallsyms_open),
	fops_hook_val(sys_newuname),
	fops_hook_val(proc_sys_read),
};

/* give each task a larger cred->security. called from stop_machine() */

#define tpe_remap_cred_security(cred) \
			c = cred; \
			old = c->security; \
			new = kmemdup(old, sizeof(struct task_security_struct), GFP_KERNEL); \
			if (!new) return -ENOMEM; \
			new->soften_mmap = 0; \
			c->security = new; \
			kfree(old);

static int tpe_remap_all_cred_security(void *data) {
	struct task_struct *g, *t;
	struct cred *c;
	struct task_security_struct *new = 0;
	void *old;

	do_each_thread(g, t) {

		if (t->cred != t->real_cred) {
			tpe_remap_cred_security((struct cred *)t->real_cred);
		}

		if (!new || new != t->cred->security) {
			tpe_remap_cred_security((struct cred *)t->cred);
		}

	} while_each_thread(g, t);

	return 0;
}

#define printfail(msg,func,ret) printk(PKPRE "%s: unable to implement protections for %s in %s() at line %d, return code %d\n", msg, func, __FUNCTION__, __LINE__, ret)

#define tpe_hook_list(hooks, val) \
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

#define tpe_unhook_list(hooks) \
	for (i = 0; i < ARRAY_SIZE(hooks); i++) { \
		fopskit_sym_unhook(&hooks[i]); \
	}

static int __init tpe_init(void) {
	int ftrace_enabled, i, ret = 0;

	ftrace_enabled = fopskit_sym_int("ftrace_enabled");

	if (!ftrace_enabled || IN_ERR(ftrace_enabled)) {
		printk(PKPRE "Unable to insert module, ftrace is not enabled.\n");
		return -ENOSYS;
	}

	ret = tpe_config_init();

	if (IN_ERR(ret))
		goto out_err;

	ret = stop_machine(tpe_remap_all_cred_security, (void *) NULL, NULL);

	if (IN_ERR(ret))
		goto out_err;

	tpe_hook_list(tpe_hooks, 1);
	tpe_hook_list(tpe_hooks_extras, 0);

	printk(PKPRE "added to kernel\n");

	return 0;

	out_err:
	printk(PKPRE "Unable to insert module, return code %d\n", ret);

	tpe_unhook_list(tpe_hooks);
	tpe_unhook_list(tpe_hooks_extras);

	return ret;
}

static void __exit tpe_exit(void) {
	int i;

	tpe_unhook_list(tpe_hooks);
	tpe_unhook_list(tpe_hooks_extras);

	tpe_config_exit();

	printk(PKPRE "removed from kernel\n");

	return;
}

module_init(tpe_init);
module_exit(tpe_exit);

MODULE_AUTHOR("Corey Henderson");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Trusted Path Execution (TPE) Module");
MODULE_VERSION("2.0.1");

