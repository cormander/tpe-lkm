
#include "module.h"

// the single most important function of all (for this module, of course). prevent
// the execution of untrusted binaries

// TODO: make the printks give more info (full path to file, pwd, gid, etc)

int tpe_allow_file(const struct file *file) {

	unsigned char *iname;
	struct inode *inode;
	uid_t uid;
	int ret = 0;

	// different versions of the kernels have a different task_struct
	// TODO: go look up when this actually changed. I just know that it did somewhere between
	//	2.6.18 and 2.6.32 :P
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	uid = current->uid;

	inode = file->f_dentry->d_parent->d_inode;
	iname = file->f_dentry->d_iname;
	#else
	uid = current_cred()->uid;

	inode = file->f_path.dentry->d_parent->d_inode;
	iname = file->f_path.dentry->d_iname;
	#endif

	// uid is not root and not trusted
	// file is not owned by root or owned by root and writable
	if (uid && !in_group_p(TPE_TRUSTED_GID) &&
		(inode->i_uid || (!inode->i_uid && ((inode->i_mode & S_IWGRP) || (inode->i_mode & S_IWOTH))))
	) {
		printk(PKPRE "Denied untrusted exec of %s by uid %d\n", iname, uid);
		ret = -EACCES;
	} else
	// a less restrictive TPE enforced even on trusted users
	if (uid &&
		((inode->i_uid && (inode->i_uid != uid)) ||
		(inode->i_mode & S_IWGRP) || (inode->i_mode & S_IWOTH))
	) {
		printk(PKPRE "Denied untrusted exec of %s by uid %d\n", iname, uid);
		ret = -EACCES;
	}

	return ret;
}

// a shortcut if we ever need to tpe check when only given a filename

int tpe_allow(const char *name) {

	struct file *file;
	int ret;

	file = open_exec(name);

	if (IS_ERR(file))
		return file;

	ret = tpe_allow_file(file);

	fput(file);

	return ret;
}

