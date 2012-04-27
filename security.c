
#include "module.h"

struct kernsym sym_security_file_mmap;
struct kernsym sym_security_file_mprotect;
struct kernsym sym_security_bprm_check;
struct kernsym sym_do_mmap_pgoff;
struct kernsym sym_do_execve;
#ifndef CONFIG_X86_32
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
struct kernsym sym_compat_do_execve;
#endif
#endif
struct kernsym sym_security_syslog;
struct kernsym sym_do_syslog;
struct kernsym sym_m_show;
struct kernsym sym_kallsyms_open;
struct kernsym sym_sys_kill;
struct kernsym sym_pid_revalidate;
struct kernsym sym_security_sysctl;
struct kernsym sym_do_rw_proc;

// it's possible to mimic execve by loading a binary into memory, mapping pages
// as executable via mmap, thus bypassing TPE protections. This prevents that.

int tpe_security_file_mmap(struct file *file, unsigned long reqprot,
		unsigned long prot, unsigned long flags,
		unsigned long addr, unsigned long addr_only) {

	int (*run)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long) = sym_security_file_mmap.run;
	int ret = 0;

	if (file && (prot & PROT_EXEC)) {
		ret = tpe_allow_file(file, "mmap");
		if (IN_ERR(ret))
			goto out;
	}

	ret = (int) run(file, reqprot, prot, flags, addr, addr_only);

	out:

	return ret;
}

// same thing as with mmap, mprotect can change the flags on already allocated memory

int tpe_security_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
		unsigned long prot) {

	int (*run)(struct vm_area_struct *, unsigned long, unsigned long) = sym_security_file_mprotect.run;
	int ret = 0;

	if (vma->vm_file && (prot & PROT_EXEC)) {
		ret = tpe_allow_file(vma->vm_file, "mprotect");
		if (IN_ERR(ret))
			goto out;
	}

	ret = run(vma, reqprot, prot);

	out:

	return ret;
}

// this is called from somewhere within do_execve, and enforces TPE on calls to exec

int tpe_security_bprm_check(struct linux_binprm *bprm) {

	int (*run)(struct linux_binprm *) = sym_security_bprm_check.run;
	int ret = 0;

	if (bprm->file) {
		ret = tpe_allow_file(bprm->file, "exec");
		if (IN_ERR(ret))
			goto out;
	}

	ret = run(bprm);

	out:

	return ret;
}

// only hijack these two functions if we can't do the above ones

unsigned long tpe_do_mmap_pgoff(struct file * file, unsigned long addr,
	unsigned long len, unsigned long prot,
	unsigned long flags, unsigned long pgoff) {

	unsigned long (*run)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long) = sym_do_mmap_pgoff.new_addr;
	unsigned long ret;

	if (file && (prot & PROT_EXEC)) {
		ret = (unsigned long) tpe_allow_file(file, "mmap");
		if (IN_ERR((int) ret))
			goto out;
	}

	ret = run(file, addr, len, prot, flags, pgoff);

	out:

	return ret;
}

int tpe_do_execve(char * filename,
	char __user *__user *argv,
	char __user *__user *envp,
	struct pt_regs * regs) {

	int (*run)(char *, char __user *__user *, char __user *__user *, struct pt_regs *) = sym_do_execve.run;
	int ret;

	ret = tpe_allow(filename, "exec");

	if (!IN_ERR(ret))
		ret = run(filename, argv, envp, regs);

	return ret;
}

#ifndef CONFIG_X86_32
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
int tpe_compat_do_execve(char * filename,
	char __user *__user *argv,
	char __user *__user *envp,
	struct pt_regs * regs) {

	int (*run)(char *, char __user *__user *, char __user *__user *, struct pt_regs *) = sym_compat_do_execve.run;
	int ret;

	ret = tpe_allow(filename, "exec");

	if (!IN_ERR(ret))
		ret = run(filename, argv, envp, regs);

	return ret;
}
#endif
#endif

void printfail(const char *name) {

	printk(PKPRE "warning: unable to implement protections for %s\n", name);

}

int tpe_m_show(struct seq_file *m, void *p) {

	int (*run)(struct seq_file *, void *) = sym_m_show.run;

	if (tpe_lsmod && !capable(CAP_SYS_MODULE))
		return -EPERM;

	return run(m, p);
}

int tpe_kallsyms_open(struct inode *inode, struct file *file) {

	int (*run)(struct inode *, struct file *) = sym_kallsyms_open.run;

	if (tpe_proc_kallsyms && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	return run(inode, file);
}

void tpe_sys_kill(int pid, int sig) {

	void (*run)(int, int) = sym_sys_kill.run;

	if (sym_sys_kill.found)
		run(pid, sig);
}

static int tpe_pid_revalidate(struct dentry *dentry, struct nameidata *nd) {

	int (*run)(struct dentry *, struct nameidata *) = sym_pid_revalidate.run;
	int ret;

	if (tpe_ps && !capable(CAP_SYS_ADMIN) &&
		dentry->d_inode && dentry->d_inode->i_uid != get_task_uid(current) &&
		dentry->d_parent->d_inode && dentry->d_parent->d_inode->i_uid != get_task_uid(current) &&
		(!tpe_ps_gid || (tpe_ps_gid && !in_group_p(tpe_ps_gid))))
		return -EPERM;

	ret = run(dentry, nd);

	return ret;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
int tpe_security_sysctl(struct ctl_table *table, int op) {

	int (*run)(struct ctl_table *, int) = sym_security_sysctl.run;
	int ret;

	// every time I have to look that this, I go: o.O
	// if the tpe_lock is on, and they're requesting a write, and the parent or grandparent ctl_table is "tpe", deny it
	if (tpe_lock && (op & MAY_WRITE) &&
		((table->parent && table->parent->procname && !strncmp("tpe", table->parent->procname, 3)) ||
		(table->parent && table->parent->parent && table->parent->parent->procname && !strncmp("tpe", table->parent->parent->procname, 3))))
		return -EPERM;

	ret = run(table, op);

	return ret;
}
#else
static ssize_t tpe_do_rw_proc(int write, struct file * file, char __user * buf,
		size_t count, loff_t *ppos) {

	char filename[MAX_FILE_LEN], *f;
	ssize_t (*run)(int, struct file *, char __user *, size_t, loff_t *) = sym_do_rw_proc.run;
	ssize_t ret;

	f = tpe_d_path(file, filename, MAX_FILE_LEN);

	if (tpe_lock && write && !strncmp("/proc/sys/tpe", f, 13))
		return -EPERM;

	ret = run(write, file, buf, count, ppos);

	return ret;
}
#endif

// hijack the needed functions. whenever possible, hijack just the LSM function

void hijack_syscalls(void) {

	int ret;

	// mmap

	ret = symbol_hijack(&sym_security_file_mmap, "security_file_mmap", (unsigned long *)tpe_security_file_mmap);

	if (IN_ERR(ret)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
		ret = symbol_hijack(&sym_do_mmap_pgoff, "do_mmap_pgoff", (unsigned long *)tpe_do_mmap_pgoff);

		if (IN_ERR(ret))
			printfail("mmap");
#else
		printfail("security_file_mmap");
#endif
	}

	// mprotect

	ret = symbol_hijack(&sym_security_file_mprotect, "security_file_mprotect", (unsigned long *)tpe_security_file_mprotect);

	if (IN_ERR(ret))
		printfail("mprotect");

	// execve

	ret = symbol_hijack(&sym_security_bprm_check, "security_bprm_check", (unsigned long *)tpe_security_bprm_check);

	if (IN_ERR(ret)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
		ret = symbol_hijack(&sym_do_execve, "do_execve", (unsigned long *)tpe_do_execve);

		if (IN_ERR(ret))
			printfail("execve");
#else
		printfail("security_bprm_check");
#endif
	}

	ret = symbol_hijack(&sym_pid_revalidate, "pid_revalidate", (unsigned long *)tpe_pid_revalidate);

	if (IN_ERR(ret))
		printfail("pid_revalidate");

#ifndef CONFIG_X86_32
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	// execve compat

	ret = symbol_hijack(&sym_compat_do_execve, "compat_do_execve", (unsigned long *)tpe_compat_do_execve);

	if (IN_ERR(ret))
		printfail("compat execve");
#endif
#endif

	// lsmod

	ret = symbol_hijack(&sym_m_show, "m_show", (unsigned long *)tpe_m_show);

	if (IN_ERR(ret))
		printfail("lsmod");

	// kallsyms

	ret = symbol_hijack(&sym_kallsyms_open, "kallsyms_open", (unsigned long *)tpe_kallsyms_open);

	if (IN_ERR(ret))
		printfail("/proc/kallsyms");

	// sysctl lock
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
	ret = symbol_hijack(&sym_security_sysctl, "security_sysctl", (unsigned long *)tpe_security_sysctl);
#else
	ret = symbol_hijack(&sym_do_rw_proc, "do_rw_proc", (unsigned long *)tpe_do_rw_proc);
#endif

	if (IN_ERR(ret))
		printfail(MODULE_NAME " sysctl lock");

	// fetch the kill syscall. don't worry about an error, nothing we can do about it
	find_symbol_address(&sym_sys_kill, "sys_kill");

}

void undo_hijack_syscalls(void) {
	symbol_restore(&sym_security_file_mmap);
	symbol_restore(&sym_security_file_mprotect);
	symbol_restore(&sym_security_bprm_check);
	symbol_restore(&sym_do_mmap_pgoff);
	symbol_restore(&sym_do_execve);
#ifndef CONFIG_X86_32
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	symbol_restore(&sym_compat_do_execve);
#endif
#endif
	symbol_restore(&sym_security_syslog);
	symbol_restore(&sym_do_syslog);
	symbol_restore(&sym_m_show);
	symbol_restore(&sym_kallsyms_open);
	symbol_restore(&sym_pid_revalidate);
	symbol_restore(&sym_security_sysctl);
	symbol_restore(&sym_do_rw_proc);
}

