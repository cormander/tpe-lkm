
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

void parent_task_walk(struct task_struct *task) {

	struct task_struct *parent;
	char filename[MAX_FILE_LEN];
	uid_t uid;

	if (task->mm) {

		#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
		uid = task->uid;
		parent = task->parent;
		#else
		uid = task->cred->uid;
		parent = task->real_parent;
		#endif

		printk("%s (uid:%d)", exe_from_mm(task->mm, filename, MAX_FILE_LEN), uid);

		if (parent && parent != task && task->pid != 1) {
			printk(", ");
			parent_task_walk(parent);
		}
	}

}

void log_denied_exec(const struct file *file) {

	char filename[MAX_FILE_LEN], *f;
	char pfilename[MAX_FILE_LEN], *pf;
	struct task_struct *parent, *grandparent;
	uid_t uid;
	uid_t puid;

	// different versions of the kernels have a different task_struct
	// TODO: go look up when this actually changed. I just know that it did somewhere between
	//	2.6.18 and 2.6.32 :P
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	uid = current->uid;

	parent = current->parent;
	puid = parent->uid;

	grandparent = parent->parent;

	f = d_path(file->f_dentry, file->f_vfsmnt, filename, MAX_FILE_LEN);
	#else
	uid = current_cred()->uid;

	parent = current->real_parent;
	puid = parent->cred->uid;

	grandparent = parent->real_parent;

	f = d_path(&file->f_path, filename, MAX_FILE_LEN);
	#endif

	pf = exe_from_mm(parent->mm, pfilename, MAX_FILE_LEN);

	printk(PKPRE "Denied untrusted exec of %s (uid:%d) by %s (uid:%d), parents: ", f, uid, pf, puid);

	// start from this tasks's grandparent, since this task and parent have already been printed
	parent_task_walk(grandparent);
	printk("\n");
}

int tpe_allow_file(const struct file *file) {

	struct inode *inode;
	uid_t uid;
	int ret = 0;

	// different versions of the kernels have a different task_struct
	// TODO: go look up when this actually changed. I just know that it did somewhere between
	//	2.6.18 and 2.6.32 :P
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	uid = current->uid;
	inode = file->f_dentry->d_parent->d_inode;
	#else
	uid = current_cred()->uid;
	inode = file->f_path.dentry->d_parent->d_inode;
	#endif

	// uid is not root and not trusted
	// file is not owned by root or owned by root and writable
	if (uid && !in_group_p(TPE_TRUSTED_GID) &&
		(inode->i_uid || (!inode->i_uid && ((inode->i_mode & S_IWGRP) || (inode->i_mode & S_IWOTH))))
	) {
		log_denied_exec(file);
		ret = -EACCES;
	} else
	// a less restrictive TPE enforced even on trusted users
	if (uid &&
		((inode->i_uid && (inode->i_uid != uid)) ||
		(inode->i_mode & S_IWGRP) || (inode->i_mode & S_IWOTH))
	) {
		log_denied_exec(file);
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

