
#include "tpe.h"

struct code_store cs_do_execve;
struct code_store cs_compat_do_execve;

int tpe_do_execve(char __user *name, char __user * __user *argv,
		char __user * __user *envp, struct pt_regs *regs) {

	int ret;

	ret = tpe_allow(name);

	if (IS_ERR(ret))
		goto out;

	stop_my_code(&cs_do_execve);

	ret = cs_do_execve.ptr(name, argv, envp, regs);

	start_my_code(&cs_do_execve);

	out:

	return ret;
}

#ifndef CONFIG_X86_32
int tpe_compat_do_execve(char __user *name, char __user * __user *argv,
		char __user * __user *envp, struct pt_regs *regs) {

	int ret;

	ret = tpe_allow(name);

	if (IS_ERR(ret))
		goto out;

	stop_my_code(&cs_compat_do_execve);

	ret = cs_compat_do_execve.ptr(name, argv, envp, regs);

	start_my_code(&cs_compat_do_execve);

	out:

	return ret;
}
#endif

