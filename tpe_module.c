
#include "tpe.h"
#include "fopskit.h"

int fopskit_sym_hook(struct symhook *);
int fopskit_sym_unhook(struct symhook *);

int tpe_allow_file(const struct file *, const char *);

int tpe_config_init(void);
void tpe_config_exit(void);

/* regs->ip gets set to here when we want to deny execution */

int tpe_donotexec(void) {
	return -EACCES;
}

#define TPE_NOEXEC regs->ip = (unsigned long)tpe_donotexec

/* mmap */

fopskit_hook_handler(security_mmap_file) {
	if (REGS_ARG1 && (REGS_ARG2 & PROT_EXEC))
		if (tpe_allow_file((struct file *)REGS_ARG1, "mmap"))
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

	file = (struct file *)REGS_ARG1;
	f = tpe_d_path(file, filename, MAX_FILE_LEN);

	if (tpe_lock && (
		!strncmp("/proc/sys/tpe", f, 13) ||
		!strcmp("/proc/sys/kernel/ftrace_enabled", f))
	)
		TPE_NOEXEC;
}

/* lsmod */

fopskit_hook_handler(m_show) {
	if (tpe_lsmod && !capable(CAP_SYS_MODULE))
		TPE_NOEXEC;
}

/* kallsyms_open */

fopskit_hook_handler(kallsyms_open) {
	if (tpe_proc_kallsyms && (tpe_paranoid || !capable(CAP_SYS_ADMIN)))
		TPE_NOEXEC;
}

/* __ptrace_may_access */

fopskit_hook_handler(__ptrace_may_access) {
	if (tpe_harden_ptrace && !UID_IS_TRUSTED(get_task_uid(current)))
		TPE_NOEXEC;
}

/* sys_newuname */

fopskit_hook_handler(sys_newuname) {
	if (tpe_hide_uname && !UID_IS_TRUSTED(get_task_uid(current)))
		TPE_NOEXEC;
}

fopskit_hook_handler(proc_sys_read) {
	char filename[MAX_FILE_LEN], *f;
	struct file *file;

	file = (struct file *)REGS_ARG1;
	f = tpe_d_path(file, filename, MAX_FILE_LEN);

	if (tpe_hide_uname && !strcmp("/proc/sys/kernel/osrelease", f))
		TPE_NOEXEC;
}

/* each call to fopskit_hook_handler() needs a corresponding entry here */

struct symhook tpe_hooks[] = {
	symhook_val(security_mmap_file),
	symhook_val(security_file_mprotect),
	symhook_val(security_bprm_check),
	symhook_val(proc_sys_write),
	symhook_val(m_show),
	symhook_val(kallsyms_open),
	symhook_val(__ptrace_may_access),
	symhook_val(sys_newuname),
	symhook_val(proc_sys_read),
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
MODULE_VERSION("2.0.0");

