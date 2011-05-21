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
#include <linux/semaphore.h>

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

#define CODESIZE 8

char jump_code[] =
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
struct code_store cs_do_mmap_pgoff;
struct code_store cs_mprotect_fixup;

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

unsigned long tpe_do_mmap_pgoff(struct file *file, unsigned long addr,
		unsigned long len, unsigned long prot,
		unsigned long flags, unsigned long pgoff)
{

	long ret;

	if (unlikely(!file || !(prot & PROT_EXEC))) {

	} else {
		ret = tpe_allow_file(file);

		if (IS_ERR(ret))
			goto out;
	}

	stop_my_code(&cs_do_mmap_pgoff);

	ret = cs_do_mmap_pgoff.ptr(file, addr, len, prot, flags, pgoff);

	start_my_code(&cs_do_mmap_pgoff);

	out:

	return ret;
}

int tpe_mprotect_fixup(struct vm_area_struct *vma, struct vm_area_struct **pprev,
	unsigned long start, unsigned long end, unsigned long newflags) {

	int ret;

	if (vma->vm_file) {
		ret = tpe_allow_file(vma->vm_file);

		if (IS_ERR(ret))
			goto out;
	}

	stop_my_code(&cs_mprotect_fixup);

	ret = cs_mprotect_fixup.ptr(vma, pprev, start, end, newflags);

	start_my_code(&cs_mprotect_fixup);

	out:

	return ret;
}

int init_tpe(void) {

	printk("TPE added to kernel\n");

	// get code sizes of function pointers;
	cs_do_execve.size = CODESIZE+sizeof(char __user *)+sizeof(char __user * __user *)+sizeof(char __user * __user *)+sizeof(struct pt_regs *);
	cs_compat_do_execve.size = CODESIZE+sizeof(char __user *)+sizeof(char __user * __user *)+sizeof(char __user * __user *)+sizeof(struct pt_regs *);
	cs_do_mmap_pgoff.size = CODESIZE+sizeof(struct file *)+sizeof(unsigned long)+sizeof(unsigned long)+sizeof(unsigned long)+sizeof(unsigned long)+sizeof(unsigned long);
	cs_mprotect_fixup.size = CODESIZE+sizeof(struct vm_area_struct *)+sizeof(struct vm_area_struct **)+sizeof(unsigned long)+sizeof(unsigned long)+sizeof(unsigned long);

	// add jump code to each jump_code struct
	memcpy(cs_do_execve.new, jump_code, cs_do_execve.size);
	memcpy(cs_compat_do_execve.new, jump_code, cs_compat_do_execve.size);
	memcpy(cs_do_mmap_pgoff.new, jump_code, cs_do_mmap_pgoff.size);
	memcpy(cs_mprotect_fixup.new, jump_code, cs_mprotect_fixup.size);

	// tell the jump_code where we want to go
	*(unsigned long *)&cs_do_execve.new[2] = (unsigned long)tpe_do_execve;
	*(unsigned long *)&cs_compat_do_execve.new[2] = (unsigned long)tpe_compat_do_execve;
	*(unsigned long *)&cs_do_mmap_pgoff.new[2] = (unsigned long)tpe_do_mmap_pgoff;
	*(unsigned long *)&cs_mprotect_fixup.new[2] = (unsigned long)tpe_mprotect_fixup;

	// assign the function to the jump_code ptr
	// TODO: figure out the address of do_execve at init_tpe(), if possible
	cs_do_execve.ptr = |addr_do_execve|;
	cs_compat_do_execve.ptr = |addr_compat_do_execve|;
	cs_do_mmap_pgoff.ptr = |addr_do_mmap_pgoff|;
	cs_mprotect_fixup.ptr = |addr_mprotect_fixup|;

	// save the bytes of the original syscall
	memcpy(cs_do_execve.orig, cs_do_execve.ptr, cs_do_execve.size);
	memcpy(cs_compat_do_execve.orig, cs_compat_do_execve.ptr, cs_compat_do_execve.size);
	memcpy(cs_do_mmap_pgoff.orig, cs_do_mmap_pgoff.ptr, cs_do_mmap_pgoff.size);
	memcpy(cs_mprotect_fixup.orig, cs_mprotect_fixup.ptr, cs_mprotect_fixup.size);

	// init the locks
	init_MUTEX(&cs_do_execve.lock);
	init_MUTEX(&cs_compat_do_execve.lock);
	init_MUTEX(&cs_do_mmap_pgoff.lock);
	init_MUTEX(&cs_mprotect_fixup.lock);

	// init the hijacks
	start_my_code(&cs_do_execve);
	start_my_code(&cs_compat_do_execve);
/*
	start_my_code(&cs_do_mmap_pgoff);
	start_my_code(&cs_mprotect_fixup);
*/

	return 0;
}

static void exit_tpe(void) {

	// stop the hijacks
	stop_my_code(&cs_do_execve);
	stop_my_code(&cs_compat_do_execve);
/*
	stop_my_code(&cs_do_mmap_pgoff);
	stop_my_code(&cs_mprotect_fixup);
*/

	printk("TPE removed from kernel\n");

	return;
}

module_init(init_tpe);
module_exit(exit_tpe);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Trusted Path Execution (TPE) Module");

