/*

Trusted Path Execution (TPE) linux kernel module

*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/syscalls.h>
#include <asm/system.h>

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

static DECLARE_MUTEX(memcpy_lock);

#define CODESIZE 12

typedef struct jump_code {
	char orig[CODESIZE];
	char new[CODESIZE]; 
};

struct jump_code jmp_do_execve;

void start_my_code(struct jump_code *jc) {
	#ifdef NEED_GPF_PROT
	GPF_DISABLE;
	#endif

	down(&memcpy_lock);

	// Overwrite the bytes with instructions to return to our new function
	memcpy(do_execve_ptr, jmp_do_execve.new, CODESIZE);

	up(&memcpy_lock);

	#ifdef NEED_GPF_PROT
	GPF_ENABLE;
	#endif
}

void stop_my_code(struct jump_code *jc) {
	#ifdef NEED_GPF_PROT
	GPF_DISABLE;
	#endif

	down(&memcpy_lock);

	// restore bytes to the original syscall address
	memcpy(do_execve_ptr, jmp_do_execve.orig, CODESIZE);

	up(&memcpy_lock);

	#ifdef NEED_GPF_PROT
	GPF_ENABLE;
	#endif
}

// TODO: make the printks give more info (full path to file, pwd, gid, etc)

int tpe_allow(const struct file *file) {

	struct inode *inode = file->f_path.dentry->d_parent->d_inode;
	const struct cred *cred = current_cred();

	// uid is not root and not trusted
	// file is not owned by root or owned by root and writable
	if (cred->uid && !in_group_p(TPE_TRUSTED_GID) &&
		(inode->i_uid || (!inode->i_uid && ((inode->i_mode & S_IWGRP) || (inode->i_mode & S_IWOTH))))
	) {
		printk("Denied untrusted exec of %s by uid %d", file->f_path.dentry->d_iname, cred->uid);
		return 0;
	}

	// a less restrictive TPE enforced even on trusted users
	if (cred->uid &&
		((inode->i_uid && (inode->i_uid != cred->uid)) ||
		(inode->i_mode & S_IWGRP) || (inode->i_mode & S_IWOTH))
	) {
		printk("Denied untrusted exec of %s by uid %d", file->f_path.dentry->d_iname, cred->uid);
		return 0;
	}

	return 1;
}

asmlinkage long tpe_execve(char __user *name, char __user * __user *argv,
		char __user * __user *envp, struct pt_regs *regs) {

	long ret;
	struct file *file;

	file = open_exec(name);

	if (IS_ERR(file))
		return file;

	if (!tpe_allow(file)) {
		ret = -EACCES;
		goto out;
	}

	// replace code at do_execve so we can use the function
	stop_my_code(&jmp_do_execve);

	ret = do_execve_ptr(name, argv, envp, regs);

	// replace jump at do_execve so further calls comes back to this function
	start_my_code(&jmp_do_execve);

	out:

	fput(file);

	return ret;
}

int init_tpe(void) {

	printk("TPE added to kernel\n");

	memcpy(jmp_do_execve.new,
		"\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
		"\xff\xe0"
		, CODESIZE);

	// tell the jump_code where we want to go
	*(unsigned long *)&jmp_do_execve.new[2] = (unsigned long)tpe_execve;

	// save the bytes of the original syscall
	memcpy(jmp_do_execve.orig, do_execve_ptr, CODESIZE);

	start_my_code(&jmp_do_execve);

	return 0;
}

static void exit_tpe(void) {

	stop_my_code(&jmp_do_execve);

	printk("TPE removed from kernel\n");

	return;
}

module_init(init_tpe);
module_exit(exit_tpe);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Trusted Path Execution (TPE) Module");

