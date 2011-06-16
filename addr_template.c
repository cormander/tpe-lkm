
#include "tpe.h"

extern void hijack_syscall(struct code_store *cs, const unsigned long code, const unsigned long addr); 

extern struct code_store cs_do_execve;
#ifndef CONFIG_X86_32
extern struct code_store cs_compat_do_execve;
#endif
extern struct code_store cs_security_file_mmap;
extern struct code_store cs_security_file_mprotect;

extern int tpe_do_execve(char __user *name, char __user * __user *argv,
		char __user * __user *envp, struct pt_regs *regs);

extern int tpe_compat_do_execve(char __user *name, char __user * __user *argv,
		char __user * __user *envp, struct pt_regs *regs);

extern int tpe_security_file_mmap(struct file *file, unsigned long reqprot,
		unsigned long prot, unsigned long flags,
		unsigned long addr, unsigned long addr_only);

extern int tpe_security_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
		unsigned long prot);

void hijack_syscalls(void) {

	hijack_syscall(&cs_do_execve, (unsigned long)tpe_do_execve, |addr_do_execve|);
#ifndef CONFIG_X86_32
	hijack_syscall(&cs_compat_do_execve, (unsigned long)tpe_compat_do_execve, |addr_compat_do_execve|);
#endif
	hijack_syscall(&cs_security_file_mmap, (unsigned long)tpe_security_file_mmap, |addr_security_file_mmap|);
	hijack_syscall(&cs_security_file_mprotect, (unsigned long)tpe_security_file_mprotect, |addr_security_file_mprotect|);

}

void undo_hijack_syscalls(void) {
	// stop the hijacks
	stop_my_code(&cs_do_execve);
#ifndef CONFIG_X86_32
	stop_my_code(&cs_compat_do_execve);
#endif
	stop_my_code(&cs_security_file_mmap);
	stop_my_code(&cs_security_file_mprotect);

}

