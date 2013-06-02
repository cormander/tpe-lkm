
#include "module.h"

struct kernsym sym_security_file_mmap;
struct kernsym sym_security_file_mprotect;
struct kernsym sym_security_bprm_check;
#if !defined(CONFIG_X86_32) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
struct kernsym sym_compat_do_execve;
#endif
struct kernsym sym_m_show;
struct kernsym sym_kallsyms_open;
struct kernsym sym_pid_revalidate;
struct kernsym sym_proc_sys_write;
struct kernsym sym_security_inode_follow_link;

// mmap

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
unsigned long tpe_security_file_mmap(struct file * file, unsigned long addr,
		unsigned long len, unsigned long prot,
		unsigned long flags, unsigned long pgoff) {

	unsigned long (*run)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long) = sym_security_file_mmap.new_addr;
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
#else
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
#endif

// execve

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
int tpe_security_bprm_check(char * filename,
	char __user *__user *argv,
	char __user *__user *envp,
	struct pt_regs * regs) {

	int (*run)(char *, char __user *__user *, char __user *__user *, struct pt_regs *) = sym_security_bprm_check.run;
	int ret;

	ret = tpe_allow(filename, "exec");

	if (!IN_ERR(ret))
		ret = run(filename, argv, envp, regs);

	return ret;
}
#else
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
#endif

// sysctl lock

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
static ssize_t tpe_proc_sys_write(int write, struct file * file, char __user * buf,
		size_t count, loff_t *ppos) {

	char filename[MAX_FILE_LEN], *f;
	ssize_t (*run)(int, struct file *, char __user *, size_t, loff_t *) = sym_proc_sys_write.run;
	ssize_t ret;

	f = tpe_d_path(file, filename, MAX_FILE_LEN);

	if (tpe_lock && write && !strncmp("/proc/sys/tpe", f, 13))
		return -EPERM;

	ret = run(write, file, buf, count, ppos);

	return ret;
}
#else
static ssize_t tpe_proc_sys_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos) {
	char filename[MAX_FILE_LEN], *f;
	ssize_t (*run)(struct file *, const char __user *, size_t, loff_t *) = sym_proc_sys_write.run;
	ssize_t ret;

	f = tpe_d_path(file, filename, MAX_FILE_LEN);

	if (tpe_lock && !strncmp("/proc/sys/tpe", f, 13))
		return -EPERM;

	ret = run(file, buf, count, ppos);

	return ret;
}
#endif

// compat execve

#if !defined(CONFIG_X86_32) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
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

// mprotect

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

// lsmod

int tpe_m_show(struct seq_file *m, void *p) {

	int (*run)(struct seq_file *, void *) = sym_m_show.run;

	if (tpe_lsmod && !capable(CAP_SYS_MODULE))
		return -EPERM;

	return run(m, p);
}

// kallsyms

int tpe_kallsyms_open(struct inode *inode, struct file *file) {

	int (*run)(struct inode *, struct file *) = sym_kallsyms_open.run;

	if (tpe_proc_kallsyms && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	return run(inode, file);
}

// ps restrict

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

// only follow symlinks if owner matches

static inline void tpe_copy_nameidata(const struct nameidata *src, struct nameidata *dst) {

	int i;

	dst->depth = src->depth;
	dst->flags = src->flags;

	dst->last_type = src->last_type;
	dst->last = src->last;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	if (src->dentry)
		dst->dentry = dget(src->dentry);

	if (src->mnt)
		dst->mnt = mntget(src->mnt);
#else
	dst->path = src->path;
	if (dst->path.dentry && dst->path.mnt)
		path_get(&dst->path);

	dst->root = src->root;
	if (dst->root.dentry && dst->root.mnt)
		path_get(&dst->root);
#endif

	for (i = 0; i < dst->depth; i++)
		dst->saved_names[i] = src->saved_names[i];
}

static inline void tpe_release_nameidata(struct nameidata *dst) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	if (dst->dentry)
		dput(dst->dentry)

	if (dst->mnt)
		mntput(dst->mnt);
#else
	if (dst->path.dentry && dst->path.mnt)
		path_put(&dst->path);

	if (dst->root.dentry && dst->root.mnt)
		path_put(&dst->root);
#endif
}

static int tpe_security_inode_follow_link(struct dentry *dentry, struct nameidata *nd) {

	int (*run)(struct dentry *, struct nameidata *) = sym_security_inode_follow_link.run;
	int ret;

	const struct inode *link_inode, *target_inode;
	void *cookie;
	struct nameidata target_nd;

	if (!tpe_harden_symlink)
		goto out;

	tpe_copy_nameidata(nd, &target_nd);

	link_inode = dentry->d_inode;

	cookie = dentry->d_inode->i_op->follow_link(dentry, &target_nd);
	if (!IS_ERR(cookie)) {
		char *s = nd_get_link(&target_nd);
		int error = 0;

		if (s != NULL)
			error = vfs_follow_link(&target_nd, s);
		if (dentry->d_inode->i_op->put_link)
			dentry->d_inode->i_op->put_link(dentry, &target_nd, cookie);
		if (error) {
			tpe_release_nameidata(&target_nd);
			return error;
		}
	}
	else {
		tpe_release_nameidata(&target_nd);
		return PTR_ERR(cookie);
	}

	target_inode = target_nd.path.dentry->d_inode;

	if (!capable(CAP_SYS_ADMIN) &&
		link_inode != NULL && target_inode != NULL &&
		link_inode->i_uid && link_inode->i_uid != target_inode->i_uid) {
		tpe_release_nameidata(&target_nd);
		return -EACCES;
	}

	tpe_release_nameidata(&target_nd);

	out:

	ret = run(dentry, nd);

	return ret;
}

void printfail(const char *name) {
	printk(PKPRE "warning: unable to implement protections for %s\n", name);
}

struct symhook {
	char *name;
	struct kernsym *sym;
	unsigned long *func;
};

struct symhook security2hook[] = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	{"do_execve", &sym_security_bprm_check, (unsigned long *)tpe_security_bprm_check},
	{"do_mmap_pgoff", &sym_security_file_mmap, (unsigned long *)tpe_security_file_mmap},
	{"do_rw_proc", &sym_proc_sys_write, (unsigned long *)tpe_proc_sys_write},
#else
	{"security_bprm_check", &sym_security_bprm_check, (unsigned long *)tpe_security_bprm_check},
	{"security_file_mmap", &sym_security_file_mmap, (unsigned long *)tpe_security_file_mmap},
	{"security_file_mprotect", &sym_security_file_mprotect, (unsigned long *)tpe_security_file_mprotect},
	{"proc_sys_write", &sym_proc_sys_write, (unsigned long *)tpe_proc_sys_write},
#endif
#if !defined(CONFIG_X86_32) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	{"compat_do_execve", &sym_compat_do_execve, (unsigned long *)tpe_compat_do_execve},
#endif
	{"pid_revalidate", &sym_pid_revalidate, (unsigned long *)tpe_pid_revalidate},
	{"m_show", &sym_m_show, (unsigned long *)tpe_m_show},
	{"kallsyms_open", &sym_kallsyms_open, (unsigned long *)tpe_kallsyms_open},
	{"security_inode_follow_link", &sym_security_inode_follow_link, (unsigned long *)tpe_security_inode_follow_link},
};

// hijack the needed functions. whenever possible, hijack just the LSM function

void hijack_syscalls(void) {

	int ret, i;

	for (i = 0; security2hook[i].func; i++) {
		ret = symbol_hijack(security2hook[i].sym, security2hook[i].name, security2hook[i].func);

		if (IN_ERR(ret))
			printfail(security2hook[i].name);
	}

}

void undo_hijack_syscalls(void) {
	int i;

	for (i = 0; security2hook[i].func; i++)
		symbol_restore(security2hook[i].sym);
}

