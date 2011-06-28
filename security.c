
#include "tpe.h"

struct kernsym sym_security_file_mmap;
struct kernsym sym_security_file_mprotect;
struct kernsym sym_security_bprm_check;

// it's possible to mimic execve by loading a binary into memory, mapping pages
// as executable via mmap, thus bypassing TPE protections. This prevents that.

int tpe_security_file_mmap(struct file *file, unsigned long reqprot,
		unsigned long prot, unsigned long flags,
		unsigned long addr, unsigned long addr_only) {

	int ret = 0;

	if (file && (prot & PROT_EXEC)) {
		ret = tpe_allow_file(file);
		if (IS_ERR(ret))
			goto out;
	}

#if WRAP_SYSCALLS
	stop_my_code(&sym_security_file_mmap);

	ret = sym_security_file_mmap.ptr(file, reqprot, prot, flags, addr, addr_only);

	start_my_code(&sym_security_file_mmap);
#endif

	out:

	return ret;
}

// same thing as with mmap, mprotect can change the flags on already allocated memory

int tpe_security_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
		unsigned long prot) {

	int ret = 0;

	if (vma->vm_file && (prot & PROT_EXEC)) {
		ret = tpe_allow_file(vma->vm_file);
		if (IS_ERR(ret))
			goto out;
	}

#if WRAP_SYSCALLS
	stop_my_code(&sym_security_file_mprotect);

	ret = sym_security_file_mprotect.ptr(vma, reqprot, prot);

	start_my_code(&sym_security_file_mprotect);
#endif

	out:

	return ret;
}

// this is called from somewhere within do_execve, and enforces TPE on calls to exec

int tpe_security_bprm_check(struct linux_binprm *bprm) {

	int ret = 0;

	if (bprm->file) {
		ret = tpe_allow_file(bprm->file);
		if (IS_ERR(ret))
			goto out;
	}

#if WRAP_SYSCALLS
	stop_my_code(&sym_security_bprm_check);

	ret = sym_security_bprm_check.ptr(bprm);

	start_my_code(&sym_security_bprm_check);
#endif

	out:

	return ret;
}

