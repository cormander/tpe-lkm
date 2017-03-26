
#include "module.h"

int symbol_ftrace(struct symhook *);
int symbol_restore(struct symhook *);

int tpe_donotexec(void) {
	return -EACCES;
}

/* mmap */

tpe_trace_handler(security_mmap_file) {
	if (REGS_ARG1(regs) && (REGS_ARG2(regs) & PROT_EXEC))
		if (tpe_allow_file((struct file *)REGS_ARG1(regs), "mmap"))
			TPE_NOEXEC;
}

/* mprotect */

tpe_trace_handler(security_file_mprotect) {
	struct vm_area_struct *vma = (struct vm_area_struct *)REGS_ARG1(regs);

	if (vma->vm_file && (REGS_ARG2(regs) & PROT_EXEC))
		if (tpe_allow_file(vma->vm_file, "mprotect"))
			TPE_NOEXEC;
}

/* execve */

tpe_trace_handler(security_bprm_check) {
	struct linux_binprm *bprm = (struct linux_binprm *)REGS_ARG1(regs);

	if (bprm->file)
		if (tpe_allow_file(bprm->file, "exec"))
			TPE_NOEXEC;
}

/* lsmod */

tpe_trace_handler(m_show) {
	if (tpe_lsmod && !capable(CAP_SYS_MODULE))
		TPE_NOEXEC;
}

/* kallsyms_open */

tpe_trace_handler(kallsyms_open) {
	if (tpe_proc_kallsyms && (tpe_paranoid || !capable(CAP_SYS_ADMIN)))
		TPE_NOEXEC;
}

/* __ptrace_may_access */

tpe_trace_handler(__ptrace_may_access) {
	if (tpe_harden_ptrace && !UID_IS_TRUSTED(__kuid_val(get_task_uid(current))))
		TPE_NOEXEC;
}

/* sys_newuname */

tpe_trace_handler(sys_newuname) {
	if (tpe_hide_uname && !UID_IS_TRUSTED(__kuid_val(get_task_uid(current))))
		TPE_NOEXEC;
}

struct symhook security2hook[] = {
	symhook_val(security_mmap_file),
	symhook_val(security_file_mprotect),
	symhook_val(security_bprm_check),
	symhook_val(m_show),
	symhook_val(kallsyms_open),
	symhook_val(__ptrace_may_access),
	symhook_val(sys_newuname),
};

#define printfail(str,ret) printk(PKPRE "warning: unable to implement protections for %s in %s() at line %d, return code %d\n", str, __FUNCTION__, __LINE__, ret)

void ftrace_syscalls(void) {
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(security2hook); i++) {
		ret = symbol_ftrace(&security2hook[i]);

		if (IN_ERR(ret))
			printfail(security2hook[i].name, ret);
	}

}

void undo_ftrace_syscalls(void) {
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(security2hook); i++) {
		ret = symbol_restore(&security2hook[i]);

		if (IN_ERR(ret))
			printfail(security2hook[i].name, ret);
	}

}

