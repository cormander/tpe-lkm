
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

#define TPE_NOEXEC if (!tpe_softmode) fopskit_return(tpe_donotexec)
#define TPE_EXTRAS_NOEXEC(val) { \
		tpe_log_denied_action(current->mm->exe_file, val, "tpe_extras", tpe_softmode-tpe_extras_ignore_softmode); \
		if (!tpe_softmode || tpe_extras_ignore_softmode) \
			fopskit_return(tpe_donotexec); \
	}

/* mmap */

fopskit_hook_handler(security_mmap_file) {
	struct file *file = (struct file *)REGS_ARG1;
	struct fopskit_cred_security *sec;
	fopskit_cred_security_ptr(sec, current->cred->security);

	if (fopskit_cred_remapped && sec->fopskit_flags) return;

	if (file && (REGS_ARG2 & PROT_EXEC))
		if (tpe_allow_file(file, "mmap"))
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
	struct fopskit_cred_security *sec;

	if (bprm->file) {
		/* load xattr flag for soften_mmap if it's there */
		if (fopskit_cred_remapped && tpe_file_getfattr(bprm->file, "mmap")) {
			fopskit_cred_security_ptr(sec, bprm->cred->security);
			sec->fopskit_flags = 1;
		}

		if (tpe_allow_file(bprm->file, "exec"))
			TPE_NOEXEC;
	}
}

/* pid_revalidate */

fopskit_hook_handler(pid_revalidate) {
	struct dentry *dentry = (struct dentry *)REGS_ARG1;

	if (!tpe_ps || (tpe_softmode && !tpe_extras_ignore_softmode)) return;

	if (!capable(CAP_SYS_ADMIN) &&
		dentry->d_inode && __kuid_val(dentry->d_inode->i_uid) != get_task_uid(current) &&
		dentry->d_parent->d_inode && __kuid_val(dentry->d_parent->d_inode->i_uid) != get_task_uid(current) &&
		(!tpe_ps_gid || (tpe_ps_gid && !in_group_p(KGIDT_INIT(tpe_ps_gid)))))
		fopskit_return(fopskit_eperm);
}

/* security_task_fix_setuid */

fopskit_hook_handler(security_task_fix_setuid) {
	struct cred *new = (struct cred *)REGS_ARG1;
	struct cred *old = (struct cred *)REGS_ARG2;

	if (tpe_restrict_setuid && !__kuid_val(new->uid) && !UID_IS_TRUSTED(__kuid_val(old->uid)))
		TPE_EXTRAS_NOEXEC("setuid");
}

/* lsmod */

fopskit_hook_handler(m_show) {
	if (tpe_lsmod && !capable(CAP_SYS_MODULE))
		TPE_EXTRAS_NOEXEC("lsmod");
}

/* kallsyms_open */

fopskit_hook_handler(kallsyms_open) {
	if (tpe_proc_kallsyms && (tpe_paranoid || !capable(CAP_SYS_ADMIN)))
		TPE_EXTRAS_NOEXEC("kallsyms");
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
			TPE_EXTRAS_NOEXEC("ptrace");
	}
}

/* sys_newuname */

fopskit_hook_handler(sys_newuname) {
	if (tpe_hide_uname && !UID_IS_TRUSTED(get_task_uid(current)))
		TPE_EXTRAS_NOEXEC("uname");
}

fopskit_hook_handler(proc_sys_read) {
	char filename[MAX_FILE_LEN], *f;
	struct file *file;

	if (tpe_hide_uname) {
		file = (struct file *)REGS_ARG1;
		f = tpe_d_path(file, filename, MAX_FILE_LEN);

		if (!strcmp("/proc/sys/kernel/osrelease", f))
			TPE_EXTRAS_NOEXEC("uname");
	}
}

/* sysctl lock */

int tpe_handler_proc_sys_write(struct file *file) {
	char filename[MAX_FILE_LEN], *f;

	f = tpe_d_path(file, filename, MAX_FILE_LEN);

	if (tpe_lock && !strncmp("/proc/sys/tpe", f, 13))
		return -EPERM;

	return 0;
}

/* each call to fopskit_hook_handler() needs a corresponding entry here */

static struct fops_hook tpe_hooks[] = {
	fops_hook_val(security_mmap_file),
	fops_hook_val(security_file_mprotect),
	fops_hook_val(security_bprm_check),
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

/* pass in our own code for proc_sys_write() */

static struct fops_cred_handler tpe_cred_handler = {
	.proc_sys_write = tpe_handler_proc_sys_write,
	.security_prepare_creds = NULL,
	.security_cred_alloc_blank = NULL,
};

static int __init tpe_init(void) {
	int i, ret;

	ret = fopskit_sym_int("ftrace_enabled");

	if (!ret || IN_ERR(ret)) {
		printk(PKPRE "Unable to insert module, ftrace is not enabled.\n");
		return -ENOSYS;
	}

	ret = fopskit_init_cred_security(&tpe_cred_handler);

	if (IN_ERR(ret))
		goto out_err;

	fopskit_hook_list(tpe_hooks, 1);
	fopskit_hook_list(tpe_hooks_extras, 0);

	ret = tpe_config_init();

	if (IN_ERR(ret))
		goto out_err;

	printk(PKPRE "added to kernel\n");

	return 0;

	out_err:
	printk(PKPRE "Unable to insert module, return code %d\n", ret);

	fopskit_unhook_list(tpe_hooks);
	fopskit_unhook_list(tpe_hooks_extras);
	fopskit_exit(ret);

	return ret;
}

static void __exit tpe_exit(void) {
	int i;

	fopskit_unhook_list(tpe_hooks);
	fopskit_unhook_list(tpe_hooks_extras);
	fopskit_exit(0);

	tpe_config_exit();

	printk(PKPRE "removed from kernel\n");

	return;
}

module_init(tpe_init);
module_exit(tpe_exit);

MODULE_AUTHOR("Corey Henderson");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Trusted Path Execution (TPE) Module");
MODULE_VERSION("2.0.2");

