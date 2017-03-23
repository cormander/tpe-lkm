
#include "module.h"

static DEFINE_SEMAPHORE(tpe_mutex);

struct kernsym sym_security_bprm_check;
struct kernsym sym_security_mmap_file;
struct kernsym sym_security_file_mprotect;

// mmap

int tpe_security_mmap_file(struct file *file, unsigned long prot, unsigned long flags) {

	if (file && (prot & PROT_EXEC))
		return tpe_allow_file(file, "mmap");

	return 0;
}

// mprotect

int tpe_security_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot) {

	if (vma->vm_file && (prot & PROT_EXEC))
		return tpe_allow_file(vma->vm_file, "mprotect");

	return 0;
}

// execve

int tpe_security_bprm_check(struct linux_binprm *bprm) {

	if (bprm->file)
		return tpe_allow_file(bprm->file, "exec");

	return 0;
}

#define printfail(str,ret) printk(PKPRE "warning: unable to implement protections for %s in %s() at line %d, return code %d\n", str, __FUNCTION__, __LINE__, ret)

struct symhook {
	char *name;
	struct kernsym *sym;
	unsigned long *func;
};

// order matters for optimization
struct symhook security2hook[] = {
	{"security_mmap_file", &sym_security_mmap_file, (unsigned long *)tpe_security_mmap_file},
	{"security_file_mprotect", &sym_security_file_mprotect, (unsigned long *)tpe_security_file_mprotect},
	{"security_bprm_check", &sym_security_bprm_check, (unsigned long *)tpe_security_bprm_check},
};

static void notrace tpe_ftrace_handler(unsigned long ip, unsigned long parent_ip,
                      struct ftrace_ops *fops, struct pt_regs *regs) {

	int i;

	for (i = 0; i < ARRAY_SIZE(security2hook); i++)
		if(security2hook[i].sym->addr == (unsigned long *)ip)
			regs->ip = (unsigned long)security2hook[i].sym->hook_addr; // redirect this return address to our hooking function

}

static struct ftrace_ops tpe_ftrace_ops __read_mostly = {
        .func = tpe_ftrace_handler,
        .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY,
};

int symbol_ftrace_ftrace(void *data) {
	struct kernsym *sym = data;
	int ret;

	ret = ftrace_set_filter_ip(&tpe_ftrace_ops, (unsigned long) sym->addr, 0, 0);

	if (IN_ERR(ret))
		return ret;

	ret = register_ftrace_function(&tpe_ftrace_ops);
	if (IN_ERR(ret))
		return ret;

	sym->ftraceed = true;

	return ret;
}

int symbol_ftrace(struct kernsym *sym, const char *symbol_name, unsigned long *code) {

	int ret;

	down(&tpe_mutex);
	preempt_disable_notrace();

	ret = find_symbol_address(sym, symbol_name);

	if (IN_ERR(ret))
		return ret;

	sym->hook_addr = code;

	//ret = stop_machine(symbol_ftrace_ftrace, sym, NULL);
	ret = symbol_ftrace_ftrace(sym);

	preempt_enable_notrace();
	up(&tpe_mutex);

	return 0;
}

int symbol_restore(struct kernsym *sym) {
	int ret;

	if (sym->ftraceed) {

		down(&tpe_mutex);
		preempt_disable_notrace();

		ret = unregister_ftrace_function(&tpe_ftrace_ops);

		if (IN_ERR(ret))
			return ret;

		ret = ftrace_set_filter_ip(&tpe_ftrace_ops, (unsigned long) sym->addr, 1, 0);

		if (IN_ERR(ret))
			return ret;

		sym->ftraceed = false;

		preempt_enable_notrace();
		up(&tpe_mutex);
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
		ret = symbol_ftrace(security2hook[i].sym, security2hook[i].name, security2hook[i].func);

		if (IN_ERR(ret))
			printfail(security2hook[i].name, ret);
	}

}

void undo_ftrace_syscalls(void) {
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(security2hook); i++) {
		ret = symbol_restore(security2hook[i].sym);
		if (IN_ERR(ret))
			printfail(security2hook[i].name, ret);
	}

}

