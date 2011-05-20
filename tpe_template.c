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

asmlinkage long (*do_execve_ptr)(char __user *name, char __user * __user *argv,
		char __user * __user *envp, struct pt_regs *regs) = (unsigned long *)|addr_do_execve|;

asmlinkage long (*compat_do_execve_ptr)(char __user *name, char __user * __user *argv,
		char __user * __user *envp, struct pt_regs *regs) = (unsigned long *)|addr_compat_do_execve|;

unsigned long (*do_mmap_pgoff_ptr)(struct file *file, unsigned long addr,
		unsigned long len, unsigned long prot,
		unsigned long flags, unsigned long pgoff) = (unsigned long *)|addr_do_mmap_pgoff|;

static DECLARE_MUTEX(memcpy_lock);

#define CODESIZE 12

typedef struct jump_code {
	char orig[CODESIZE];
	char new[CODESIZE]; 
	long *ptr;
};

struct jump_code jmp_do_execve;
struct jump_code jmp_compat_do_execve;
struct jump_code jmp_do_mmap_pgoff;

void start_my_code(struct jump_code *jc) {

	down(&memcpy_lock);

	#ifdef NEED_GPF_PROT
	GPF_DISABLE;
	#endif

	// Overwrite the bytes with instructions to return to our new function
	memcpy(jc->ptr, jc->new, CODESIZE);

	#ifdef NEED_GPF_PROT
	GPF_ENABLE;
	#endif

	up(&memcpy_lock);
}

void stop_my_code(struct jump_code *jc) {

	down(&memcpy_lock);

	#ifdef NEED_GPF_PROT
	GPF_DISABLE;
	#endif

	// restore bytes to the original syscall address
	memcpy(jc->ptr, jc->orig, CODESIZE);

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

	// replace code at do_execve so we can use the function
	stop_my_code(&jmp_do_execve);

	ret = do_execve_ptr(name, argv, envp, regs);

	// replace jump at do_execve so further calls comes back to this function
	start_my_code(&jmp_do_execve);

	out:

	return ret;
}

asmlinkage long tpe_compat_do_execve(char __user *name, char __user * __user *argv,
		char __user * __user *envp, struct pt_regs *regs) {

	long ret;

	ret = tpe_allow(name);

	if (IS_ERR(ret))
		goto out;

	// replace code at compat_do_execve so we can use the function
	stop_my_code(&jmp_compat_do_execve);

	ret = compat_do_execve_ptr(name, argv, envp, regs);

	// replace jump at do_execve so further calls comes back to this function
	start_my_code(&jmp_compat_do_execve);

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

	stop_my_code(&jmp_do_mmap_pgoff);

	ret = do_mmap_pgoff_ptr(file, addr, len, prot, flags, pgoff);

	start_my_code(&jmp_do_mmap_pgoff);

	out:

	return ret;
}

int init_tpe(void) {

	printk("TPE added to kernel\n");

	// add jump code to each jump_code struct
	memcpy(jmp_do_execve.new,
		"\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
		"\xff\xe0"
		, CODESIZE);

	memcpy(jmp_compat_do_execve.new,
		"\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
		"\xff\xe0"
		, CODESIZE);

	memcpy(jmp_do_mmap_pgoff.new,
		"\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
		"\xff\xe0"
		, CODESIZE);

	// tell the jump_code where we want to go
	*(unsigned long *)&jmp_do_execve.new[2] = (unsigned long)tpe_do_execve;
	*(unsigned long *)&jmp_compat_do_execve.new[2] = (unsigned long)tpe_compat_do_execve;
	*(unsigned long *)&jmp_do_mmap_pgoff.new[2] = (unsigned long)tpe_do_mmap_pgoff;

	// assign the function to the jump_code ptr
	jmp_do_execve.ptr = do_execve_ptr;
	jmp_compat_do_execve.ptr = compat_do_execve_ptr;
	jmp_do_mmap_pgoff.ptr = do_mmap_pgoff_ptr;

	// save the bytes of the original syscall
	memcpy(jmp_do_execve.orig, do_execve_ptr, CODESIZE);
	memcpy(jmp_compat_do_execve.orig, compat_do_execve_ptr, CODESIZE);
	memcpy(jmp_do_mmap_pgoff.orig, do_mmap_pgoff_ptr, CODESIZE);

	// init the hijacks
	start_my_code(&jmp_do_execve);
	start_my_code(&jmp_compat_do_execve);
	start_my_code(&jmp_do_mmap_pgoff);

	return 0;
}

static void exit_tpe(void) {

	// stop the hijacks
	stop_my_code(&jmp_do_execve);
	stop_my_code(&jmp_compat_do_execve);
	stop_my_code(&jmp_do_mmap_pgoff);

	printk("TPE removed from kernel\n");

	return;
}

module_init(init_tpe);
module_exit(exit_tpe);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Trusted Path Execution (TPE) Module");

