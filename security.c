
#include "module.h"

int tpe_donotexec(void) {
	return -EACCES;
}

#ifdef CONFIG_X86_64
#define REGS_ARG1(r) r->di
#define REGS_ARG2(r) r->si
#define REGS_ARG3(r) r->dx
#else
#error "Arch not currently supported."
#endif

#define tpe_trace_handler(val) \
	static void notrace tpe_##val(unsigned long ip, unsigned long parent_ip, \
		struct ftrace_ops *fops, struct pt_regs *regs)

// mmap

tpe_trace_handler(security_mmap_file) {
	if (REGS_ARG1(regs) && (REGS_ARG2(regs) & PROT_EXEC))
		if (tpe_allow_file((struct file *)REGS_ARG1(regs), "mmap"))
			regs->ip = (unsigned long)tpe_donotexec;
}

// mprotect

tpe_trace_handler(security_file_mprotect) {
	struct vm_area_struct *vma = (struct vm_area_struct *)REGS_ARG1(regs);

	if (vma->vm_file && (REGS_ARG2(regs) & PROT_EXEC))
		if (tpe_allow_file(vma->vm_file, "mprotect"))
			regs->ip = (unsigned long)tpe_donotexec;
}

// execve

tpe_trace_handler(security_bprm_check) {
	struct linux_binprm *bprm = (struct linux_binprm *)REGS_ARG1(regs);

	if (bprm->file)
		if (tpe_allow_file(bprm->file, "exec"))
			regs->ip = (unsigned long)tpe_donotexec;
}

// lsmod

tpe_trace_handler(m_show) {
	if (tpe_lsmod && !capable(CAP_SYS_MODULE))
		regs->ip = (unsigned long)tpe_donotexec;
}

struct symhook {
	char *name;
	struct kernsym *sym;
	struct ftrace_ops *fops;
};

#define struct_kernsym(val) struct kernsym sym_##val

#define struct_ftrace_ops(val) \
static struct ftrace_ops fops_##val __read_mostly = { \
	.func = tpe_##val, \
	.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY, \
}

#define tpe_make_structs(val) \
	struct_kernsym(val); \
	struct_ftrace_ops(val);

tpe_make_structs(security_mmap_file);
tpe_make_structs(security_file_mprotect);
tpe_make_structs(security_bprm_check);
tpe_make_structs(m_show);

#define symhook_val(val) \
	{#val, &sym_##val, &fops_##val}

struct symhook security2hook[] = {
	symhook_val(security_mmap_file),
	symhook_val(security_file_mprotect),
	symhook_val(security_bprm_check),
	symhook_val(m_show),
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

#define printfail(str,ret) printk(PKPRE "warning: unable to implement protections for %s in %s() at line %d, return code %d\n", str, __FUNCTION__, __LINE__, ret)

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

