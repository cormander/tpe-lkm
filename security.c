
#include "module.h"

struct kernsym sym_security_file_mmap;
struct kernsym sym_security_file_mprotect;
struct kernsym sym_security_bprm_check;
struct kernsym sym_do_mmap_pgoff;
struct kernsym sym_do_execve;
#ifndef CONFIG_X86_32
struct kernsym sym_compat_do_execve;
#endif
struct kernsym sym_security_syslog;
struct kernsym sym_do_syslog;
struct kernsym sym_m_show;
struct kernsym sym_kallsyms_open;
struct kernsym sym_sys_kill;

// it's possible to mimic execve by loading a binary into memory, mapping pages
// as executable via mmap, thus bypassing TPE protections. This prevents that.

int tpe_security_file_mmap(struct file *file, unsigned long reqprot,
		unsigned long prot, unsigned long flags,
		unsigned long addr, unsigned long addr_only) {

	int ret = 0;

	if (file && (prot & PROT_EXEC)) {
		ret = tpe_allow_file(file, "mmap");
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
		ret = tpe_allow_file(vma->vm_file, "mprotect");
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
		ret = tpe_allow_file(bprm->file, "exec");
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
		ret = tpe_allow_file(file, "mmap");
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

	ret = tpe_allow(filename, "exec");

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

	ret = tpe_allow(filename, "exec");

	if (!IS_ERR(ret))
		ret = sym_compat_do_execve.run(filename, argv, envp, regs);

	out:

	return ret;
}
#endif

void printfail(const char *name) {

	printk(PKPRE "warning: unable to implement protections for %s\n", name);

}

int tpe_security_syslog(int type, bool from_file) {

	if (tpe_dmesg && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	return sym_security_syslog.run(type, from_file);
}


int tpe_do_syslog(int type, char __user *buf, int len, bool from_file) {

	if (tpe_dmesg && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	return sym_do_syslog.run(type, buf, len, from_file);
}

int tpe_m_show(struct seq_file *m, void *p) {

	if (tpe_lsmod && !capable(CAP_SYS_MODULE))
		return -EPERM;

	return sym_m_show.run(m, p);
}

int tpe_kallsyms_open(struct inode *inode, struct file *file) {

	if (tpe_proc_kallsyms && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	return sym_kallsyms_open.run(inode, file);
}

void tpe_sys_kill(int sig, int pid) {
	if (sym_sys_kill.found)
		sym_sys_kill.run(sig, pid);
}

// hijack the needed functions. whenever possible, hijack just the LSM function

void hijack_syscalls(void) {

	int ret;

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

	// dmesg

	ret = symbol_hijack(&sym_security_syslog, "security_syslog", (unsigned long)tpe_security_syslog);

	if (IS_ERR(ret)) {

		ret = symbol_hijack(&sym_do_syslog, "do_syslog", (unsigned long)tpe_do_syslog);

		if (IS_ERR(ret))
			printfail("dmesg");

	}

	// lsmod

	ret = symbol_hijack(&sym_m_show, "m_show", (unsigned long)tpe_m_show);

	if (IS_ERR(ret))
		printfail("lsmod");

	// kallsyms

	ret = symbol_hijack(&sym_kallsyms_open, "kallsyms_open", (unsigned long)tpe_kallsyms_open);

	if (IS_ERR(ret))
		printfail("/proc/kallsyms");

	// fetch the kill syscall. don't worry about an error, nothing we can do about it
	find_symbol_address(&sym_sys_kill, "sys_kill");

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
	symbol_restore(&sym_security_syslog);
	symbol_restore(&sym_do_syslog);
	symbol_restore(&sym_m_show);
	symbol_restore(&sym_kallsyms_open);
}

