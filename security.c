
#include "tpe.h"

struct kernsym sym_security_file_mmap;
struct kernsym sym_security_file_mprotect;
struct kernsym sym_security_bprm_check;
struct kernsym sym_do_execve;
struct kernsym sym_do_mmap_pgoff;
#ifndef CONFIG_X86_32
struct kernsym sym_compat_do_execve;
#endif

extern struct mutex gpf_lock;

// it's possible to mimic execve by loading a binary into memory, mapping pages
// as executable via mmap, thus bypassing TPE protections. This prevents that.

int tpe_security_file_mmap(struct file *file, unsigned long reqprot,
		unsigned long prot, unsigned long flags,
		unsigned long addr, unsigned long addr_only) {

	int ret = 0;

	if (file && (prot & PROT_EXEC)) {
		ret = tpe_allow_file(file);
		if (IS_ERR(ret))
			goto out;
	}

	ret = sym_security_file_mmap.run(file, reqprot, prot, flags, addr, addr_only);

	out:

	return ret;
}

// same thing as with mmap, mprotect can change the flags on already allocated memory

int tpe_security_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
		unsigned long prot) {

	int ret = 0;

	if (vma->vm_file && (prot & PROT_EXEC)) {
		ret = tpe_allow_file(vma->vm_file);
		if (IS_ERR(ret))
			goto out;
	}

	ret = sym_security_file_mprotect.run(vma, reqprot, prot);

	out:

	return ret;
}

// this is called from somewhere within do_execve, and enforces TPE on calls to exec

int tpe_security_bprm_check(struct linux_binprm *bprm) {

	int ret = 0;

	if (bprm->file) {
		ret = tpe_allow_file(bprm->file);
		if (IS_ERR(ret))
			goto out;
	}

	ret = sym_security_bprm_check.run(bprm);

	out:

	return ret;
}

// only hijack these two functions if we can't do the above ones

unsigned long tpe_do_mmap_pgoff(struct file * file, unsigned long addr,
	unsigned long len, unsigned long prot,
	unsigned long flags, unsigned long pgoff) {

	unsigned long ret;

	if (file && (prot & PROT_EXEC)) {
		ret = tpe_allow_file(file);
		if (IS_ERR(ret))
			goto out;
	}

	ret = sym_do_mmap_pgoff.run(file, addr, len, prot, flags, pgoff);

	out:

	return ret;
}

int tpe_do_execve(char * filename,
	char __user *__user *argv,
	char __user *__user *envp,
	struct pt_regs * regs) {

	int ret;

	ret = tpe_allow(filename);

	if (!IS_ERR(ret))
		ret = sym_do_execve.run(filename, argv, envp, regs);

	out:

	return ret;
}

#ifndef CONFIG_X86_32
int tpe_compat_do_execve(char * filename,
	char __user *__user *argv,
	char __user *__user *envp,
	struct pt_regs * regs) {

	int ret;

	ret = tpe_allow(filename);

	if (!IS_ERR(ret))
		ret = sym_compat_do_execve.run(filename, argv, envp, regs);

	out:

	return ret;
}
#endif

void printfail(const char *name) {

	printk("[tpe] warning: unable to implement protections for %s\n", name);

}

// hijack the needed functions. whenever possible, hijack just the LSM function

void hijack_syscalls(void) {

	int ret;

	mutex_init(&gpf_lock);

	// mmap

	ret = symbol_hijack(&sym_security_file_mmap, "security_file_mmap", (unsigned long)tpe_security_file_mmap);

	if (IS_ERR(ret)) {

		ret = symbol_hijack(&sym_do_mmap_pgoff, "do_mmap_pgoff", (unsigned long)tpe_do_mmap_pgoff);

		if (IS_ERR(ret))
			printfail("mmap");

	}

	// mprotect

	ret = symbol_hijack(&sym_security_file_mprotect, "security_file_mprotect", (unsigned long)tpe_security_file_mprotect);

	if (IS_ERR(ret))
		printfail("mprotect");

	// execve

	ret = symbol_hijack(&sym_security_bprm_check, "security_bprm_check", (unsigned long)tpe_security_bprm_check);

	if (IS_ERR(ret)) {

		ret = symbol_hijack(&sym_do_execve, "do_execve", (unsigned long)tpe_do_execve);

		if (IS_ERR(ret))
			printfail("execve");

	}

#ifndef CONFIG_X86_32

	// execve compat

	ret = symbol_hijack(&sym_compat_do_execve, "compat_do_execve", (unsigned long)tpe_compat_do_execve);

	if (IS_ERR(ret))
		printfail("compat execve");

#endif

	return 0;
}

void undo_hijack_syscalls(void) {
	symbol_restore(&sym_security_file_mmap);
	symbol_restore(&sym_security_file_mprotect);
	symbol_restore(&sym_security_bprm_check);
	symbol_restore(&sym_do_mmap_pgoff);
	symbol_restore(&sym_do_execve);
#ifndef CONFIG_X86_32
	symbol_restore(&sym_compat_do_execve);
#endif
}

