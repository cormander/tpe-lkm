
#include "module.h"

struct kernsym sym_security_bprm_check;
struct kernsym sym_security_mmap_file;
struct kernsym sym_security_file_mprotect;
struct kernsym sym_m_show;

int tpe_donotexec(void) {
	return -EACCES;
}

// mmap

static void notrace tpe_security_mmap_file(unsigned long ip, unsigned long parent_ip,
		      struct ftrace_ops *fops, struct pt_regs *regs) {

	//struct file *file = (struct file *)regs->di;
	//unsigned long prot = (unsigned long)regs->si;

	if (regs->di && (regs->si & PROT_EXEC))
		if (tpe_allow_file((struct file *)regs->di, "mmap"))
			regs->ip = (unsigned long)tpe_donotexec;
}

// mprotect

static void notrace tpe_security_file_mprotect(unsigned long ip, unsigned long parent_ip,
			struct ftrace_ops *fops, struct pt_regs *regs) {

	struct vm_area_struct *vma = (struct vm_area_struct *)regs->di;
	//unsigned long prot = (unsigned long)regs->dx;

	if (vma->vm_file && (regs->dx & PROT_EXEC))
		if (tpe_allow_file(vma->vm_file, "mprotect"))
			regs->ip = (unsigned long)tpe_donotexec;
}

// execve

static void notrace tpe_security_bprm_check(unsigned long ip, unsigned long parent_ip,
			struct ftrace_ops *fops, struct pt_regs *regs) {

	struct linux_binprm *bprm = (struct linux_binprm *)regs->di;

	if (bprm->file)
		if (tpe_allow_file(bprm->file, "exec"))
			regs->ip = (unsigned long)tpe_donotexec;
}

static void notrace tpe_m_show(unsigned long ip, unsigned long parent_ip,
			struct ftrace_ops *fops, struct pt_regs *regs) {

	if (tpe_lsmod && !capable(CAP_SYS_MODULE))
		regs->ip = (unsigned long)tpe_donotexec;
}

#define printfail(str,ret) printk(PKPRE "warning: unable to implement protections for %s in %s() at line %d, return code %d\n", str, __FUNCTION__, __LINE__, ret)

static struct ftrace_ops fops_security_mmap_file __read_mostly = {
	.func = tpe_security_mmap_file,
	.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY,
};

static struct ftrace_ops fops_security_file_mprotect __read_mostly = {
	.func = tpe_security_file_mprotect,
	.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY,
};

static struct ftrace_ops fops_security_bprm_check __read_mostly = {
	.func = tpe_security_bprm_check,
	.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY,
};

static struct ftrace_ops fops_m_show __read_mostly = {
	.func = tpe_m_show,
	.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY,
};

struct symhook {
	char *name;
	struct kernsym *sym;
	struct ftrace_ops *fops;
};

// order matters for optimization
struct symhook security2hook[] = {
	{"security_mmap_file", &sym_security_mmap_file, &fops_security_mmap_file},
	{"security_file_mprotect", &sym_security_file_mprotect, &fops_security_file_mprotect},
	{"security_bprm_check", &sym_security_bprm_check, &fops_security_bprm_check},
	{"m_show", &sym_m_show, &fops_m_show},
};

int symbol_ftrace(const char *symbol_name, struct kernsym *sym, struct ftrace_ops *fops) {

	int ret;

	ret = find_symbol_address(sym, symbol_name);

	if (IN_ERR(ret))
		return ret;

	preempt_disable_notrace();

	ret = ftrace_set_filter_ip(fops, (unsigned long) sym->addr, 0, 0);

	if (IN_ERR(ret))
		return ret;

	ret = register_ftrace_function(fops);

	if (IN_ERR(ret))
		return ret;

	sym->ftraced = true;

	preempt_enable_notrace();

	return 0;
}

int symbol_restore(struct kernsym *sym, struct ftrace_ops *fops) {
	int ret;

	if (sym->ftraced) {

		preempt_disable_notrace();

		ret = unregister_ftrace_function(fops);

		if (IN_ERR(ret))
			return ret;

		ret = ftrace_set_filter_ip(fops, (unsigned long) sym->addr, 1, 0);

		if (IN_ERR(ret))
			return ret;

		sym->ftraced = false;

		preempt_enable_notrace();
	}

	if (sym->name_alloc) {
		malloc_free(sym->name);
		sym->name_alloc = false;
	}

	return 0;
}

// ftrace the needed functions. whenever possible, ftrace just the LSM function

void ftrace_syscalls(void) {

	int ret, i;

	for (i = 0; i < ARRAY_SIZE(security2hook); i++) {
		ret = symbol_ftrace(security2hook[i].name, security2hook[i].sym, security2hook[i].fops);

		if (IN_ERR(ret))
			printfail(security2hook[i].name, ret);
	}

}

void undo_ftrace_syscalls(void) {
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(security2hook); i++) {
		ret = symbol_restore(security2hook[i].sym, security2hook[i].fops);
		if (IN_ERR(ret))
			printfail(security2hook[i].name, ret);
	}

}

