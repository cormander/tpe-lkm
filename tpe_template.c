/*

Trusted Path Execution (TPE) linux kernel module

*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
#include <linux/sem.h>
#else
#include <linux/semaphore.h>
#endif

/*

 set NEED_GPF_PROT depending on your CPU and kernel version:

 * If it's set to zero when you need it, you will get "BUG: unable to handle
   kernel paging request", this module won't function, and you won't be able
   to remove it w/o rebooting.

 * If it's set when you don't, you'll hang or crash your system

*/

#define NEED_GPF_PROT 1

#define TPE_TRUSTED_GID 1337

// these are to prevent "general protection fault"s from occurring when we
// write to kernel memory
#define GPF_DISABLE write_cr0 (read_cr0 () & (~ 0x10000))
#define GPF_ENABLE write_cr0 (read_cr0 () | 0x10000)

#define CODESIZE 12

char jump_code[] =
	"\xb8\x00\x00\x00\x00"	// movl $0, %eax
	"\xff\xe0"		// jump *%eax
	;

char jump_code64[] =
	"\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00"	// movq $0, %rax
	"\xff\xe0"					// jump *%rax
	;

typedef struct code_store {
	int size;
	char new[1024];
	char orig[1024];
	long (*ptr)();
	struct semaphore lock;
};

struct code_store cs_do_execve;
struct code_store cs_compat_do_execve;

void start_my_code(struct code_store *cs) {

	down(&cs->lock);

	#ifdef NEED_GPF_PROT
	GPF_DISABLE;
	#endif

	// Overwrite the bytes with instructions to return to our new function
	memcpy(cs->ptr, cs->new, cs->size);

	#ifdef NEED_GPF_PROT
	GPF_ENABLE;
	#endif

	up(&cs->lock);
}

void stop_my_code(struct code_store *cs) {

	down(&cs->lock);

	#ifdef NEED_GPF_PROT
	GPF_DISABLE;
	#endif

	// restore bytes to the original syscall address
	memcpy(cs->ptr, cs->orig, cs->size);

	#ifdef NEED_GPF_PROT
	GPF_ENABLE;
	#endif

	up(&cs->lock);
}

// TODO: make the printks give more info (full path to file, pwd, gid, etc)

int tpe_allow_file(const struct file *file) {

	unsigned char *iname;
	struct inode *inode;
	uid_t uid;
	long ret = 0;

	// different versions of the kernels have a different task_struct
	// TODO: go look up when this actually changed. I just know that it did somewhere between
	//       2.6.18 and 2.6.32 :P
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
		printk("Denied untrusted exec of %s by uid %d\n", iname, uid);
		ret = -EACCES;
	} else
	// a less restrictive TPE enforced even on trusted users
	if (uid &&
		((inode->i_uid && (inode->i_uid != uid)) ||
		(inode->i_mode & S_IWGRP) || (inode->i_mode & S_IWOTH))
	) {
		printk("Denied untrusted exec of %s by uid %d\n", iname, uid);
		ret = -EACCES;
	}

	return ret;
}

int tpe_allow(const char *name) {

	struct file *file;
	long ret;

	file = open_exec(name);

	if (IS_ERR(file))
		return file;

	ret = tpe_allow_file(file);

	fput(file);

	return ret;
}

asmlinkage long tpe_do_execve(char __user *name, char __user * __user *argv,
		char __user * __user *envp, struct pt_regs *regs) {

	long ret;

	ret = tpe_allow(name);

	if (IS_ERR(ret))
		goto out;

	stop_my_code(&cs_do_execve);

	ret = cs_do_execve.ptr(name, argv, envp, regs);

	start_my_code(&cs_do_execve);

	out:

	return ret;
}

asmlinkage long tpe_compat_do_execve(char __user *name, char __user * __user *argv,
		char __user * __user *envp, struct pt_regs *regs) {

	long ret;

	ret = tpe_allow(name);

	if (IS_ERR(ret))
		goto out;

	stop_my_code(&cs_compat_do_execve);

	ret = cs_compat_do_execve.ptr(name, argv, envp, regs);

	start_my_code(&cs_compat_do_execve);

	out:

	return ret;
}

void hijack_syscall(struct code_store *cs, unsigned long code) {

	int pos;

	// TODO - verify this is OK
	cs->size = CODESIZE;

	// jump code is depends on arch
	if (sizeof(long) == 4) {
		memcpy(cs->new, jump_code, cs->size);
		pos = 1;
	} else {
		memcpy(cs->new, jump_code64, cs->size);
		pos = 2;
	}

	// tell the jump_code where we want to go
	*(unsigned long *)&cs->new[pos] = (unsigned long)code;

	// save the bytes of the original syscall
	memcpy(cs->orig, cs->ptr, cs->size);

	// init the lock
	init_MUTEX(&cs->lock);

	// init the hijack
	start_my_code(cs);

}

int init_tpe(void) {

	printk("TPE added to kernel\n");

	cs_do_execve.ptr = |addr_do_execve|;
	hijack_syscall(&cs_do_execve, (unsigned long)tpe_do_execve);

	cs_compat_do_execve.ptr = |addr_compat_do_execve|;
	hijack_syscall(&cs_compat_do_execve, (unsigned long)tpe_compat_do_execve);

	return 0;
}

static void exit_tpe(void) {

	// stop the hijacks
	stop_my_code(&cs_do_execve);
	stop_my_code(&cs_compat_do_execve);

	printk("TPE removed from kernel\n");

	return;
}

module_init(init_tpe);
module_exit(exit_tpe);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Trusted Path Execution (TPE) Module");

