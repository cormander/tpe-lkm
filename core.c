
#include "module.h"

// the single most important function of all (for this module, of course). prevent
// the execution of untrusted binaries

// determine the executed file from the task's mmap area

char *exe_from_mm(struct mm_struct *mm, char *buf, int len) {

	struct vm_area_struct *vma;
	char *p;

	down_read(&mm->mmap_sem);

	vma = mm->mmap;

	while (vma) {
		if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file)
			break;
		vma = vma->vm_next;
	}

	if (vma && vma->vm_file)
		#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
		p = d_path(vma->vm_file->f_dentry, vma->vm_file->f_vfsmnt, buf, len);
		#else
		p = d_path(&vma->vm_file->f_path, buf, len);
		#endif

	up_read(&mm->mmap_sem);

	return p;
}

int tpe_allow_file(const struct file *file) {

	char filename[MAX_FILE_LEN], *f;
	char pfilename[MAX_FILE_LEN], *pf;
	struct inode *inode;
	uid_t uid;
	uid_t puid;
	int ret = 0;

	// different versions of the kernels have a different task_struct
	// TODO: go look up when this actually changed. I just know that it did somewhere between
	//	2.6.18 and 2.6.32 :P
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	uid = current->uid;
	puid = current->parent->uid;

	inode = file->f_dentry->d_parent->d_inode;

	f = d_path(file->f_dentry, file->f_vfsmnt, filename, MAX_FILE_LEN);
	pf = exe_from_mm(current->parent->mm, pfilename, MAX_FILE_LEN);
	#else
	uid = current_cred()->uid;
	puid = current->real_parent->cred->uid;

	inode = file->f_path.dentry->d_parent->d_inode;

	f = d_path(&file->f_path, filename, MAX_FILE_LEN);
	pf = exe_from_mm(current->real_parent->mm, pfilename, MAX_FILE_LEN);
	#endif

	// uid is not root and not trusted
	// file is not owned by root or owned by root and writable
	if (uid && !in_group_p(TPE_TRUSTED_GID) &&
		(inode->i_uid || (!inode->i_uid && ((inode->i_mode & S_IWGRP) || (inode->i_mode & S_IWOTH))))
	) {
		printk(PKPRE "Denied untrusted exec of %s (uid:%d), parent %s (uid:%d)\n", f, uid, pf, puid);
		ret = -EACCES;
	} else
	// a less restrictive TPE enforced even on trusted users
	if (uid &&
		((inode->i_uid && (inode->i_uid != uid)) ||
		(inode->i_mode & S_IWGRP) || (inode->i_mode & S_IWOTH))
	) {
		printk(PKPRE "Denied untrusted exec of %s (uid:%d), parent %s (uid:%d)\n", f, uid, pf, puid);
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

