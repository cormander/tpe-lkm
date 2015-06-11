
#include "module.h"

struct kernsym sym_do_mmap_pgoff;
struct kernsym sym_security_file_mprotect;
struct kernsym sym_security_bprm_check;
struct kernsym sym_m_show;
struct kernsym sym_kallsyms_open;
struct kernsym sym_pid_revalidate;
struct kernsym sym_proc_sys_write;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
struct kernsym sym_security_inode_follow_link;
struct kernsym sym_security_inode_link;
#endif
struct kernsym sym_security_task_fix_setuid;
#endif

// mmap

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
unsigned long tpe_do_mmap_pgoff(struct file * file, unsigned long addr,
		unsigned long len, unsigned long prot,
		unsigned long flags, unsigned long pgoff) {

	unsigned long (*run)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long) = sym_do_mmap_pgoff.run;
	unsigned long ret;

	if (file && (prot & PROT_EXEC)) {
		ret = tpe_allow_file(file, "mmap");
		if (IN_ERR((int) ret))
			goto out;
	}

	ret = run(file, addr, len, prot, flags, pgoff);

	out:

	return ret;
}
#else
unsigned long tpe_do_mmap_pgoff(struct file *file, unsigned long addr,
        unsigned long len, unsigned long prot, unsigned long flags,
        unsigned long pgoff, unsigned long *populate) {

	unsigned long (*run)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long *) = sym_do_mmap_pgoff.run;
	unsigned long ret;

	if (file && (prot & PROT_EXEC)) {
		ret = tpe_allow_file(file, "mmap");
		if (IN_ERR((int) ret))
			goto out;
	}

	ret = run(file, addr, len, prot, flags, pgoff, populate);

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
		dentry->d_inode && __kuid_val(dentry->d_inode->i_uid) != __kuid_val(get_task_uid(current)) &&
		dentry->d_parent->d_inode && __kuid_val(dentry->d_parent->d_inode->i_uid) != __kuid_val(get_task_uid(current)) &&
		(!tpe_ps_gid || (tpe_ps_gid && !in_group_p(KGIDT_INIT(tpe_ps_gid)))))
		return -EPERM;

	ret = run(dentry, nd);

	return ret;
}

// no harden setuid or link support in EL5
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)

// and harden link it upstream in EL7
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)

// only follow symlinks if owner matches

#define TPE_FLAGS_CLONED		0x10000000
#define TPE_FLAGS_FREE_PATH		0x20000000
#define TPE_FLAGS_FREE_ROOT		0x40000000

static inline void tpe_copy_nameidata(const struct nameidata *src, struct nameidata *dst) {

	int i;

	dst->depth = src->depth;
	dst->flags = src->flags | TPE_FLAGS_CLONED;

	dst->last_type = src->last_type;
	dst->last = src->last;

	for (i = 0; i < ARRAY_SIZE(src->saved_names); i++)
		dst->saved_names[i] = src->saved_names[i];

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	if (src->dentry || src->mnt)
		dst->flags |= TPE_FLAGS_FREE_PATH;

	if (src->dentry)
		dst->dentry = dget(src->dentry);
	else
		dst->dentry = NULL;

	if (src->mnt)
		dst->mnt = mntget(src->mnt);
	else
		dst->mnt = NULL;
#else
	dst->path = src->path;
	if (dst->path.dentry && dst->path.mnt) {
		dst->flags |= TPE_FLAGS_FREE_PATH;
		path_get(&dst->path);
	}

	dst->root = src->root;
	if (dst->root.dentry && dst->root.mnt) {
		dst->flags |= TPE_FLAGS_FREE_ROOT;
		path_get(&dst->root);
	}
#endif
}

static inline void tpe_release_nameidata(struct nameidata *dst) {
	if (!(dst->flags & TPE_FLAGS_CLONED)) {
		printk(PKPRE "warning: attempted to release nameidata handle %p not owned by tpe!\n", dst);
		return;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	if (!(dst->flags & TPE_FLAGS_FREE_PATH))
		return;

	if (dst->dentry)
		dput(dst->dentry);

	if (dst->mnt)
		mntput(dst->mnt);
#else
	if ((dst->flags & TPE_FLAGS_FREE_PATH))
		path_put(&dst->path);

	if ((dst->flags & TPE_FLAGS_FREE_ROOT))
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

	/* we are dealing with a cloned nameidata, prevent recursion */
	if ((nd->flags & TPE_FLAGS_CLONED))
		goto out;

	tpe_copy_nameidata(nd, &target_nd);

	link_inode = dentry->d_inode;

	cookie = dentry->d_inode->i_op->follow_link(dentry, &target_nd);
	if (!IS_ERR(cookie)) {
		char *s = nd_get_link(&target_nd);
		int error = 0;

		if (s != NULL && target_nd.last_type != LAST_BIND)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
			error = vfs_follow_link
#else
				nd_set_link
#endif
				(&target_nd, s);
		else if (target_nd.last_type == LAST_BIND) {
			int status;
			struct dentry *child_dentry = target_nd.path.dentry;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
			if (!(child_dentry->d_sb->s_type->fs_flags & FS_REVAL_DOT))
#else
			if (!child_dentry->d_op->d_weak_revalidate(child_dentry, child_dentry->d_sb->s_type->fs_flags))
#endif
				goto exit_revalidate;
 
			status = child_dentry->d_op->d_revalidate(child_dentry,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
				&target_nd
#else
				0			
#endif
				);

			if (status > 0)
				goto exit_revalidate;

			if (!status)
				d_invalidate(child_dentry);
		}

		exit_revalidate:

		if (dentry->d_inode->i_op->put_link)
			dentry->d_inode->i_op->put_link(dentry, &target_nd, cookie);

		if (error)
			return error;
	}
	else
		return PTR_ERR(cookie);

	target_inode = target_nd.path.dentry->d_inode;

	if (!capable(CAP_SYS_ADMIN) &&
		link_inode != NULL && target_inode != NULL &&
		__kuid_val(link_inode->i_uid) && __kuid_val(link_inode->i_uid) != __kuid_val(target_inode->i_uid)) {
		tpe_release_nameidata(&target_nd);
		return -EACCES;
	}

	tpe_release_nameidata(&target_nd);

	out:

	ret = run(dentry, nd);

	return ret;
}

// hardlink protection based on Yama

static int tpe_generic_permission(struct inode *inode, int mask) {

	int ret;

	if (inode->i_op->permission)
		ret = inode->i_op->permission(inode, mask);
	else
		ret = generic_permission(inode, mask
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
			, inode->i_op->check_acl
#endif
		);

	return ret;
}

static int tpe_security_inode_link(struct dentry *old_dentry, struct inode *dir,
                                   struct dentry *new_dentry) {

	int (*run)(struct dentry *, struct inode *, struct dentry *) = sym_security_inode_link.run;
	int ret;

	struct inode *inode = old_dentry->d_inode;
	const int mode = inode->i_mode;
	const struct cred *cred = current_cred();

	if (!tpe_harden_hardlinks)
		goto out;

	if (__kuid_val(cred->fsuid) != __kuid_val(inode->i_uid) &&
		(!S_ISREG(mode) || (mode & S_ISUID) ||
		((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) ||
		(tpe_generic_permission(inode, MAY_READ | MAY_WRITE))) &&
		!capable(CAP_FOWNER)) {
		return -EPERM;
	}

	out:

	ret = run(old_dentry, dir, new_dentry);

	return ret;
}
#endif // EL7 upstream link protection

// setuid escalation denial

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
int tpe_security_task_fix_setuid(uid_t id0, uid_t id1, uid_t id2, int flags) {
	int (*run)(uid_t, uid_t, uid_t, int) = sym_security_task_fix_setuid.run;
	int ret;
	const struct cred *cred = current_cred();

	if (tpe_restrict_setuid && !id0 && !UID_IS_TRUSTED(cred->uid))
		return -EPERM;

	ret = run(id0, id1, id2, flags);

	return ret;
}
#else
int tpe_security_task_fix_setuid(struct cred *new, const struct cred *old, int flags) {
	int (*run)(struct cred *, const struct cred *, int) = sym_security_task_fix_setuid.run;
	int ret;
 
	if (tpe_restrict_setuid && !__kuid_val(new->uid) && !UID_IS_TRUSTED(__kuid_val(old->uid)))
		return -EPERM;

	ret = run(new, old, flags);

	return ret;
}
#endif // no harden setuid or link support in EL5
#endif // EL5

void printfail(const char *name) {
	printk(PKPRE "warning: unable to implement protections for %s\n", name);
}

struct symhook {
	char *name;
	struct kernsym *sym;
	unsigned long *func;
};

struct symhook security2hook[] = {
	{"do_mmap_pgoff", &sym_do_mmap_pgoff, (unsigned long *)tpe_do_mmap_pgoff},
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	{"do_execve", &sym_security_bprm_check, (unsigned long *)tpe_security_bprm_check},
	{"do_rw_proc", &sym_proc_sys_write, (unsigned long *)tpe_proc_sys_write},
#else
	{"security_bprm_check", &sym_security_bprm_check, (unsigned long *)tpe_security_bprm_check},
	{"security_file_mprotect", &sym_security_file_mprotect, (unsigned long *)tpe_security_file_mprotect},
	{"proc_sys_write", &sym_proc_sys_write, (unsigned long *)tpe_proc_sys_write},
#endif
	{"pid_revalidate", &sym_pid_revalidate, (unsigned long *)tpe_pid_revalidate},
	{"m_show", &sym_m_show, (unsigned long *)tpe_m_show},
	{"kallsyms_open", &sym_kallsyms_open, (unsigned long *)tpe_kallsyms_open},
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
	{"security_inode_follow_link", &sym_security_inode_follow_link, (unsigned long *)tpe_security_inode_follow_link},
	{"security_inode_link", &sym_security_inode_link, (unsigned long *)tpe_security_inode_link},
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
	{"security_task_setuid", &sym_security_task_fix_setuid, (unsigned long *)tpe_security_task_fix_setuid},
#else
	{"security_task_fix_setuid", &sym_security_task_fix_setuid, (unsigned long *)tpe_security_task_fix_setuid},
#endif
#endif
};

// hijack the needed functions. whenever possible, hijack just the LSM function

void hijack_syscalls(void) {

	int ret, i;

	for (i = 0; i < ARRAY_SIZE(security2hook); i++) {
		ret = symbol_hijack(security2hook[i].sym, security2hook[i].name, security2hook[i].func);

		if (IN_ERR(ret))
			printfail(security2hook[i].name);
	}

}

void undo_hijack_syscalls(void) {
	int i;

	for (i = 0; i < ARRAY_SIZE(security2hook); i++)
		symbol_restore(security2hook[i].sym);
}

