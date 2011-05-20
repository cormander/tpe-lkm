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

// Different versions of the kernels have a different task_struct, so if you
// get a compile error here about it not having member "cred", set this to 1
// TODO: make this based on kernel version, not distro, and figure out which
// version it actually changed
#define RHEL5 0

// TODO: figure out the address of do_execve at init_tpe(), if possible

asmlinkage long (*ptr_do_execve)(char __user *name, char __user * __user *argv,
		char __user * __user *envp, struct pt_regs *regs) = (unsigned long *)|addr_do_execve|;

asmlinkage long (*ptr_compat_do_execve)(char __user *name, char __user * __user *argv,
		char __user * __user *envp, struct pt_regs *regs) = (unsigned long *)|addr_compat_do_execve|;

unsigned long (*ptr_do_mmap_pgoff)(struct file *file, unsigned long addr,
		unsigned long len, unsigned long prot,
		unsigned long flags, unsigned long pgoff) = (unsigned long *)|addr_do_mmap_pgoff|;

static DECLARE_MUTEX(memcpy_lock);

#define CODESIZE 12

char jump_code[] =
	"\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00"	// movq $0, %rax
	"\xff\xe0"					// jump *%rax
	;

typedef struct code_store {
	char orig[CODESIZE];
	char new[CODESIZE]; 
	long *ptr;
};

struct code_store cs_do_execve;
struct code_store cs_compat_do_execve;
struct code_store cs_do_mmap_pgoff;

void start_my_code(struct code_store *cs) {

	down(&memcpy_lock);

	#ifdef NEED_GPF_PROT
	GPF_DISABLE;
	#endif

	// Overwrite the bytes with instructions to return to our new function
	memcpy(cs->ptr, cs->new, CODESIZE);

	#ifdef NEED_GPF_PROT
	GPF_ENABLE;
	#endif

	up(&memcpy_lock);
}

void stop_my_code(struct code_store *cs) {

	down(&memcpy_lock);

	#ifdef NEED_GPF_PROT
	GPF_DISABLE;
	#endif

	// restore bytes to the original syscall address
	memcpy(cs->ptr, cs->orig, CODESIZE);

	#ifdef NEED_GPF_PROT
	GPF_ENABLE;
	#endif

	up(&memcpy_lock);
}

// TODO: make the printks give more info (full path to file, pwd, gid, etc)

int tpe_allow_file(const struct file *file) {

	const struct cred *cred;
	struct inode *inode;
	long ret = 0;

	cred = current_cred();

	inode = file->f_path.dentry->d_parent->d_inode;

	// uid is not root and not trusted
	// file is not owned by root or owned by root and writable
	if (cred->uid && !in_group_p(TPE_TRUSTED_GID) &&
		(inode->i_uid || (!inode->i_uid && ((inode->i_mode & S_IWGRP) || (inode->i_mode & S_IWOTH))))
	) {
		printk("Denied untrusted exec of %s by uid %d\n", file->f_path.dentry->d_iname, cred->uid);
		ret = -EACCES;
	} else
	// a less restrictive TPE enforced even on trusted users
	if (cred->uid &&
		((inode->i_uid && (inode->i_uid != cred->uid)) ||
		(inode->i_mode & S_IWGRP) || (inode->i_mode & S_IWOTH))
	) {
		printk("Denied untrusted exec of %s by uid %d\n", file->f_path.dentry->d_iname, cred->uid);
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

	ret = ptr_do_execve(name, argv, envp, regs);

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

	ret = ptr_compat_do_execve(name, argv, envp, regs);

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

	ret = ptr_do_mmap_pgoff(file, addr, len, prot, flags, pgoff);

	start_my_code(&cs_do_mmap_pgoff);

	out:

	return ret;
}

int init_tpe(void) {

	printk("TPE added to kernel\n");

	// add jump code to each jump_code struct
	memcpy(cs_do_execve.new, jump_code, CODESIZE);
	memcpy(cs_compat_do_execve.new, jump_code, CODESIZE);
	memcpy(cs_do_mmap_pgoff.new, jump_code, CODESIZE);

	// tell the jump_code where we want to go
	*(unsigned long *)&cs_do_execve.new[2] = (unsigned long)tpe_do_execve;
	*(unsigned long *)&cs_compat_do_execve.new[2] = (unsigned long)tpe_compat_do_execve;
	*(unsigned long *)&cs_do_mmap_pgoff.new[2] = (unsigned long)tpe_do_mmap_pgoff;

	// assign the function to the jump_code ptr
	cs_do_execve.ptr = ptr_do_execve;
	cs_compat_do_execve.ptr = ptr_compat_do_execve;
	cs_do_mmap_pgoff.ptr = ptr_do_mmap_pgoff;

	// save the bytes of the original syscall
	memcpy(cs_do_execve.orig, ptr_do_execve, CODESIZE);
	memcpy(cs_compat_do_execve.orig, ptr_compat_do_execve, CODESIZE);
	memcpy(cs_do_mmap_pgoff.orig, ptr_do_mmap_pgoff, CODESIZE);

	// init the hijacks
	start_my_code(&cs_do_execve);
	start_my_code(&cs_compat_do_execve);
	start_my_code(&cs_do_mmap_pgoff);

	return 0;
}

static void exit_tpe(void) {

	// stop the hijacks
	stop_my_code(&cs_do_execve);
	stop_my_code(&cs_compat_do_execve);
	stop_my_code(&cs_do_mmap_pgoff);

	printk("TPE removed from kernel\n");

	return;
}

module_init(init_tpe);
module_exit(exit_tpe);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Trusted Path Execution (TPE) Module");

