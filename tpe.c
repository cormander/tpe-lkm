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
                char __user * __user *envp, struct pt_regs *regs) = (unsigned long *)0xffffffff81174f20;

static DECLARE_MUTEX(memcpy_lock);

#define CODESIZE 12

// the place to save what jump_code will overwrite
char original_code[CODESIZE];
char jump_code[CODESIZE] = 
    "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00" /* movq $0, %rax */
    "\xff\xe0"                                 /* jump *%rax */
        ;

// TODO: lock/unlock kernel as nessisary

void start_my_execve(void) {
	#ifdef NEED_GPF_PROT
	GPF_DISABLE;
	#endif

	spinlock_t mr_lock = SPIN_LOCK_UNLOCKED;
	unsigned long flags;
	spin_lock_irqsave(&mr_lock, flags);

	down(&memcpy_lock);

	// Overwrite the bytes with instructions to return to our new function
	memcpy(do_execve_ptr, jump_code, CODESIZE);

	up(&memcpy_lock);

	spin_unlock_irqrestore(&mr_lock, flags);

	#ifdef NEED_GPF_PROT
	GPF_ENABLE;
	#endif
}

void stop_my_execve(void) {
	#ifdef NEED_GPF_PROT
	GPF_DISABLE;
	#endif

	down(&memcpy_lock);

	// restore bytes to the original syscall address
	memcpy(do_execve_ptr, original_code, CODESIZE);

	up(&memcpy_lock);

	#ifdef NEED_GPF_PROT
	GPF_ENABLE;
	#endif
}

asmlinkage long tpe_execve(char __user *name, char __user * __user *argv,
		char __user * __user *envp, struct pt_regs *regs) {

	long ret;
	struct file *file;
	struct inode *inode;
	const struct cred *cred;

	file = open_exec(name);

	if (file == NULL) {
		return -ENOENT;
	}

	inode = file->f_path.dentry->d_parent->d_inode;

	// TODO: ifdef RHEL5, use current->uid instead of cred->uid
	cred = current_cred();

	if (cred->uid &&
		(inode->i_uid || (!inode->i_uid && ((inode->i_mode & S_IWGRP) ||
		(inode->i_mode & S_IWOTH))))
	) {
		fput(file);
		printk("Denied untrusted exec of %s by uid %d\n", name, cred->uid);
		return -EACCES;
	}

	fput(file);

	// replace code at do_execve so we can use the function
	stop_my_execve();

	ret = do_execve_ptr(name, argv, envp, regs);

	// replace jump at do_execve so further calls comes back to this function
	start_my_execve();

	return ret;
}

int init_tpe(void) {

	printk("TPE added to kernel\n");

	// tell the jump_code where we want to go
	*(unsigned long *)&jump_code[2] = (unsigned long)tpe_execve;

	// save the bytes of the original syscall
	memcpy(original_code, do_execve_ptr, CODESIZE);

	start_my_execve();

	return 0;
}

static void exit_tpe(void) {

	stop_my_execve();

	printk("TPE removed from kernel\n");

	return;
}

module_init(init_tpe);
module_exit(exit_tpe);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Trusted Path Execution (TPE) Module");

