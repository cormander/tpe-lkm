
#include "module.h"

// the single most important function of all (for this module, of course). prevent
// the execution of untrusted binaries

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
#define get_task_uid(task) task->uid
#define get_task_parent(task) task->parent
#else
#define get_task_uid(task) task->cred->uid
#define get_task_parent(task) task->real_parent
#endif

unsigned long tpe_alert_wtime = 0;
unsigned long tpe_alert_fyet = 0;

// d_path changed argument types. lame

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
#define tpe_d_path(file, buf, len) d_path(file->f_dentry, file->f_vfsmnt, buf, len);
#else
#define tpe_d_path(file, buf, len) d_path(&file->f_path, buf, len);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
#define get_inode(file) file->f_dentry->d_inode;
#define get_parent_inode(file) file->f_dentry->d_parent->d_inode;
#else
#define get_inode(file) file->f_path.dentry->d_inode;
#define get_parent_inode(file) file->f_path.dentry->d_parent->d_inode;
#endif

// determine the executed file from the task's mmap area

char *exe_from_mm(struct mm_struct *mm, char *buf, int len) {

	struct vm_area_struct *vma;
	char *p = NULL;

	down_read(&mm->mmap_sem);

	vma = mm->mmap;

	while (vma) {
		if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file)
			break;
		vma = vma->vm_next;
	}

	if (vma && vma->vm_file)
		p = tpe_d_path(vma->vm_file, buf, len);

	up_read(&mm->mmap_sem);

	return p;
}

// recursivly walk the task's parent until we reach init

void parent_task_walk(struct task_struct *task) {

	struct task_struct *parent;
	char filename[MAX_FILE_LEN];

	if (task && task->mm) {

		parent = get_task_parent(task);

		printk("%s (uid:%d)", exe_from_mm(task->mm, filename, MAX_FILE_LEN), get_task_uid(task));

		if (parent && task->pid != 1) {
			printk(", ");
			parent_task_walk(parent);
		}
	}

}

// lookup pathnames and log that an exec was denied

int log_denied_exec(const struct file *file, const char *method) {

	char filename[MAX_FILE_LEN], *f;
	char pfilename[MAX_FILE_LEN], *pf;
	struct task_struct *parent;

	if (!tpe_log)
		goto nolog;

	// rate-limit the tpe logging
	if (!tpe_alert_wtime || jiffies - tpe_alert_wtime > tpe_log_floodtime * HZ) {
		tpe_alert_wtime = jiffies;
		tpe_alert_fyet = 0;
	} else if ((jiffies - tpe_alert_wtime < tpe_log_floodtime * HZ) && (tpe_alert_fyet < tpe_log_floodburst)) {
		tpe_alert_fyet++;
	} else if (tpe_alert_fyet == tpe_log_floodburst) {
		tpe_alert_wtime = jiffies;
		tpe_alert_fyet++;
		printk(PKPRE "more alerts, logging disabled for %d seconds\n", tpe_log_floodtime);
		goto nolog;
	} else goto nolog;

	parent = get_task_parent(current);

	f = tpe_d_path(file, filename, MAX_FILE_LEN);

	pf = exe_from_mm(parent->mm, pfilename, MAX_FILE_LEN);

	printk(PKPRE "%s untrusted %s of %s (uid:%d) by %s (uid:%d), parents: ",
		( tpe_softmode ? "Would deny" : "Denied" ),
		method,
		f,
		get_task_uid(current),
		pf,
		get_task_uid(parent)
	);

	// start from this tasks's grandparent, since this task and parent have already been printed
	parent_task_walk(get_task_parent(parent));
	printk("\n");

	nolog:

	if (get_task_uid(current) && tpe_kill) {
		tpe_sys_kill(current->pid, SIGKILL);
		tpe_sys_kill(get_task_parent(current)->pid, SIGKILL);
	}


	if (tpe_softmode)
		return 0;
	else
		return -EACCES;
}

// get down to business and check that this file is allowed to be executed

#define INODE_IS_WRITABLE(inode) ((inode->i_mode & S_IWGRP) || (inode->i_mode & S_IWOTH))
#define INODE_IS_TRUSTED(inode) (inode->i_uid == 0 || (tpe_admin_gid && inode->i_gid == tpe_admin_gid))

int tpe_allow_file(const struct file *file, const char *method) {

	struct inode *inode, *p_inode;
	uid_t uid;

	if (tpe_dmz_gid && in_group_p(tpe_dmz_gid))
		return log_denied_exec(file, method);

	uid = get_task_uid(current);

	inode = get_inode(file);
	p_inode = get_parent_inode(file);

	// uid is not root and not trusted
	// file is not owned by root or owned by root and writable
	if (uid && !in_group_p(tpe_trusted_gid) &&
		(!INODE_IS_TRUSTED(p_inode) || (INODE_IS_TRUSTED(p_inode) && INODE_IS_WRITABLE(p_inode)) ||
		(tpe_check_file && (!INODE_IS_TRUSTED(inode) || INODE_IS_WRITABLE(inode))))
	) {
		return log_denied_exec(file, method);
	} else
	// a less restrictive TPE enforced even on trusted users
	if (tpe_strict && uid &&
		((!INODE_IS_TRUSTED(p_inode) && (p_inode->i_uid != uid)) || INODE_IS_WRITABLE(p_inode) ||
		(tpe_check_file && ((!INODE_IS_TRUSTED(inode) && (inode->i_uid != uid)) || INODE_IS_WRITABLE(inode))))
	) {
		return log_denied_exec(file, method);
	}
	else
	// paranoia, paranoia, everybody's coming to get me...
	// enforce TPE on the root user for non-root owned files and or group/world writable files
	if (tpe_paranoid && uid == 0 &&
		(!INODE_IS_TRUSTED(p_inode) || INODE_IS_WRITABLE(p_inode) ||
		(tpe_check_file && (!INODE_IS_TRUSTED(inode) || INODE_IS_WRITABLE(inode))))
	) {
		return log_denied_exec(file, method);
	}

	return 0;
}

// call tpe_allow_file on the given filename

int tpe_allow(const char *name, const char *method) {

	struct file *file;
	int ret;

	file = open_exec(name);

	if (IS_ERR(file))
		return (int) file;

	ret = tpe_allow_file(file, method);

	fput(file);

	return ret;
}

