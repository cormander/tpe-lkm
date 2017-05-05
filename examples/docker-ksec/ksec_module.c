
#include "ksec.h"

#define DOCKER_DAEMON_PATH "/usr/bin/dockerd"
#define DOCKER_LIB_PATH "/var/lib/docker"
#define DOCKER_LIB_PATH_LEN 15

/* whitelist the docker daemon */

static inline bool iam_docker_daemon(const char *file) {
	char taskname[MAX_FILE_LEN], *t;

	if (!current->mm) return true;

	t = exe_from_mm(current->mm, taskname, MAX_FILE_LEN);

	if (!IS_ERR(t) && strcmp(t, DOCKER_DAEMON_PATH)) {
		printk(PKPRE "%s was denied access to %s\n", t, file);
		return false;
	}

	return true;
}

/* protect docker lib from anything but the docker daemon */

fopskit_hook_handler(security_file_permission) {
	struct file *file = (struct file *)REGS_ARG1;
	char filename[MAX_FILE_LEN], *f;

	f = ksec_d_path(file, filename, MAX_FILE_LEN);

	/* protect the swarm key */
	if (!IS_ERR(f) && !strncmp(f, DOCKER_LIB_PATH, DOCKER_LIB_PATH_LEN)) {
		if (!iam_docker_daemon(f))
			fopskit_return(fopskit_eacces);
	}

}

/* lock ftrace in an enabled state */

fopskit_hook_handler(proc_sys_write) {
	char filename[MAX_FILE_LEN], *f;
	struct file *file = (struct file *)REGS_ARG1;

	f = ksec_d_path(file, filename, MAX_FILE_LEN);

	if (!IS_ERR(f) && !strcmp("/proc/sys/kernel/ftrace_enabled", f)) {
		printk(PKPRE "denied the disabling of ftrace\n");
		fopskit_return(fopskit_eacces)
	}

}

/* each call to fopskit_hook_handler() needs a corresponding entry here */

static struct fops_hook ksec_hooks[] = {
	fops_hook_val(proc_sys_write),
	fops_hook_val(security_file_permission),
};

static int __init ksec_init(void) {
	int i, ret;

	if (fopskit_sym_int("ftrace_enabled") != 1) {
		printk(PKPRE "Unable to insert module, ftrace is not enabled.\n");
		return -ENOSYS;
	}

	fopskit_hook_list(ksec_hooks, 1);

	printk(PKPRE "added to kernel\n");

	return 0;

	out_err:
	printk(PKPRE "Unable to insert module, return code %d\n", ret);

	fopskit_unhook_list(ksec_hooks);

	return ret;
}

static void __exit ksec_exit(void) {
	int i;

	fopskit_unhook_list(ksec_hooks);

	printk(PKPRE "removed from kernel\n");

	return;
}

module_init(ksec_init);
module_exit(ksec_exit);

MODULE_AUTHOR("Corey Henderson");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("docker-ksec");
MODULE_VERSION("1.0");

