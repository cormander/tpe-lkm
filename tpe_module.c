
#include "tpe.h"
#include "fopskit.h"

/* regs->ip gets set to here when we want to deny execution */

int tpe_donotexec(void) {

	/* if not a root process and kill is enabled, kill it */
	if (tpe_kill && get_task_uid(current)) {
		(void)send_sig_info(SIGKILL, NULL, current);
		/* only kill the parent if it isn't root */
		if (get_task_uid(get_task_parent(current)))
			(void)send_sig_info(SIGKILL, NULL, get_task_parent(current));
	}

	return -EACCES;
}

#define TPE_NOEXEC if (!tpe_softmode) regs->ip = (unsigned long)tpe_donotexec
#define TPE_NOEXEC_LOG(val) if (tpe_log_denied_action(current->mm->exe_file, val, "tpe_extras")) TPE_NOEXEC;

/* mmap */

fopskit_hook_handler(security_mmap_file) {
	struct file *file = (struct file *)REGS_ARG1;

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

	if (bprm->file)
		if (tpe_allow_file(bprm->file, "exec"))
			TPE_NOEXEC;
}

/* sysctl locks */

fopskit_hook_handler(proc_sys_write) {
	char filename[MAX_FILE_LEN], *f;
	struct file *file;

	if (tpe_lock) {
		file = (struct file *)REGS_ARG1;
		f = tpe_d_path(file, filename, MAX_FILE_LEN);

		if (!strncmp("/proc/sys/tpe", f, 13) ||
			!strcmp("/proc/sys/kernel/ftrace_enabled", f))
			TPE_NOEXEC_LOG("sysctl_tpe");
	}
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
		TPE_NOEXEC_LOG("kallsyms_open");
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

struct fops_hook tpe_hooks[] = {
	fops_hook_val(security_mmap_file),
	fops_hook_val(security_file_mprotect),
	fops_hook_val(security_bprm_check),
	fops_hook_val(proc_sys_write),
	fops_hook_val(pid_revalidate),
	fops_hook_val(security_task_fix_setuid),
	fops_hook_val(m_show),
	fops_hook_val(kallsyms_open),
	fops_hook_val(security_ptrace_access_check),
	fops_hook_val(sys_newuname),
	fops_hook_val(proc_sys_read),
};

/* allow the user to load this module without the sysctl table */

int sysctl = 1;

module_param(sysctl, int, 0);

#define printfail(str,ret) printk(PKPRE "warning: unable to implement protections for %s in %s() at line %d, return code %d\n", str, __FUNCTION__, __LINE__, ret)

static int __init tpe_init(void) {
	int i, ret = 0;

	if (sysctl) {
		ret = tpe_config_init();

		if (IN_ERR(ret))
			return ret;
	}

	for (i = 0; i < ARRAY_SIZE(tpe_hooks); i++) {
		ret = fopskit_sym_hook(&tpe_hooks[i]);

		if (IN_ERR(ret))
			printfail(tpe_hooks[i].name, ret);
	}

	printk(PKPRE "added to kernel\n");

	return ret;
}

static void __exit tpe_exit(void) {
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(tpe_hooks); i++) {
		ret = fopskit_sym_unhook(&tpe_hooks[i]);

		if (IN_ERR(ret))
			printfail(tpe_hooks[i].name, ret);
	}

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

