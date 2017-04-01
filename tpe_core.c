
#include "tpe.h"

unsigned long tpe_alert_wtime = 0;
unsigned long tpe_alert_fyet = 0;

#ifdef CONFIG_TPE_XATTR

/* check if there's a security.tpe extended file attribute */

int tpe_file_getfattr(const struct file *file, const char *method) {
	char context[MAX_FILE_LEN], buffer[MAX_FILE_LEN], *b, *c;
	char attr[MAX_FILE_LEN] = "soften_";
	struct inode *inode = get_inode(file);
	int i, ret;

	/* verify getxattr is supported */
	if (!inode->i_op->getxattr) return 0;

	ret = inode->i_op->getxattr(get_dentry(file),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
		inode,
#endif
		"security.tpe", context, MAX_FILE_LEN);

	if (IN_ERR(ret))
		return 0;

	context[ret] = '\0';
	strcat(attr, method);

	b = buffer;
	strncpy(b, context, MAX_FILE_LEN);

	while ((c = strsep(&b, ":"))) {
		i = (int)strlen(c);
		if (!strncmp(c, attr, i))
			return 1;
	}

	return 0;
}

/* check this task for the extended file attribute */

int tpe_getfattr_task(struct task_struct *task, const char *method) {

	if (task && task->mm && task->mm->exe_file)
		return tpe_file_getfattr(task->mm->exe_file, method);

	return 0;
}
#else
int tpe_getfattr_task(struct task_struct *task, const char *method) {
	return 0;
}
#endif

/* lookup pathnames and log that an exec was denied */

int tpe_log_denied_action(const struct file *file, const char *method, const char *reason) {
	char filename[MAX_FILE_LEN], buffer[MAX_FILE_LEN], *f, *b;
	struct task_struct *parent, *task;
	int c = 0;

	/* if this file or its parent has the soften flag for this method, trust it */
	if (tpe_file_getfattr(file, method) || tpe_getfattr_task(current, method))
		return 0;

	if (!tpe_log)
		goto nolog;

	/* rate-limit the tpe logging */
	if (!tpe_alert_wtime || jiffies - tpe_alert_wtime > tpe_log_floodtime * HZ) {
		tpe_alert_wtime = jiffies;
		tpe_alert_fyet = 0;
	} else if ((jiffies - tpe_alert_wtime < tpe_log_floodtime * HZ) && (tpe_alert_fyet < tpe_log_floodburst)) {
		tpe_alert_fyet++;
	} else if (tpe_alert_fyet == tpe_log_floodburst) {
		tpe_alert_wtime = jiffies;
		tpe_alert_fyet++;
		printk(PKPRE "more alerts, logging disabled for %d seconds\n", tpe_log_floodtime);
		goto nolog;
	} else goto nolog;

	f = tpe_d_path(file, filename, MAX_FILE_LEN);
	b = exe_from_mm(current->mm, buffer, MAX_FILE_LEN);

	printk(PKPRE "%s untrusted %s of %s (uid:%d) by %s (uid:%d), parents: ",
		( tpe_softmode ? "Would deny" : "Denied" ),
		method,
		(!IS_ERR(f) ? f : "<d_path failed>"),
		get_task_uid(current),
		(!IS_ERR(b) ? b : "<d_path failed>"),
		get_task_uid(current)
	);

	/* recursively walk the task's parent until we reach init */
	task = get_task_parent(current);

	walk:

	if (task && task->mm) {
		c++;

		if (tpe_log_max && c > tpe_log_max) {
			printk("tpe log_max %d reached", tpe_log_max);
			goto walk_out;
		}

		parent = get_task_parent(task);

		f = exe_from_mm(task->mm, filename, MAX_FILE_LEN);

		printk("%s (uid:%d)", (!IS_ERR(f) ? f : "<d_path failed>"), get_task_uid(task));

		if (parent && task->pid != 1) {
			printk(", ");
			task = parent;
			goto walk;
		}
	}

	/* if we get here on the first pass, there are no additional parents */
	if (c == 0) {
		printk("(none)");
	}

	walk_out:
	printk(". Deny reason: %s\n", reason);

	if (tpe_log_verbose) {
		strcpy(buffer, "soften_");
		strcat(buffer, method);

		/* for exec calls, they also need mmap, and report the actual file itself */
		if (!strcmp(method, "exec")) {
			strcat(buffer, ":soften_mmap");
			f = tpe_d_path(file, filename, MAX_FILE_LEN);
		} else {
			f = exe_from_mm(current->mm, filename, MAX_FILE_LEN);
		}

		printk(PKPRE "If this %s was legitimate and you cannot correct the behavior, an exception can be made to allow this by running; setfattr -n security.tpe -v \"%s\" %s. To silence this message, run; sysctl tpe.log_verbose = 0\n",
			method, buffer, (!IS_ERR(f) ? f : "<d_path failed>"));
	}

	nolog:

	return 1;
}

/* get down to business and check that this file is allowed to be executed */

int tpe_allow_file(const struct file *file, const char *method) {
	char filename[MAX_FILE_LEN], path[TPE_PATH_LEN], *f, *p, *c;
	struct inode *inode;
	int i;

	if (tpe_dmz_gid && in_group_p(KGIDT_INIT(tpe_dmz_gid)))
		return tpe_log_denied_action(file, method, "uid in dmz_gid");

	/* if user is not trusted, enforce the trusted path */
	if (!UID_IS_TRUSTED(get_task_uid(current))) {

		/* if trusted_apps is non-empty, allow exec if the task matches the full path */
		if (strlen(tpe_trusted_apps)) {
			p = path;
			strncpy(p, tpe_trusted_apps, TPE_PATH_LEN);

			f = tpe_d_path(file, filename, MAX_FILE_LEN);

			while ((c = strsep(&p, ",")))
				if (!IN_ERR(f) && !strcmp(c, f))
					return 0;
		}

		/* if hardcoded_path is non-empty, deny exec if the file is outside of any of those directories */
		if (strlen(tpe_hardcoded_path)) {
			p = path;
			strncpy(p, tpe_hardcoded_path, TPE_PATH_LEN);

			f = tpe_d_path(file, filename, MAX_FILE_LEN);

			while ((c = strsep(&p, ":"))) {
				i = (int)strlen(c);
				if (!strncmp(c, f, i) && !strstr(&f[i+1], "/"))
					return 0;
			}

			return tpe_log_denied_action(file, method, "outside of hardcoded_path");

		}

		inode = get_parent_inode(file);

		if (!INODE_IS_TRUSTED(inode))
			return tpe_log_denied_action(file, method, "directory uid not trusted");

		if (INODE_IS_WRITABLE(inode))
			return tpe_log_denied_action(file, method, "directory is writable");

		if (tpe_check_file) {

			inode = get_inode(file);

			if (!INODE_IS_TRUSTED(inode))
				return tpe_log_denied_action(file, method, "file uid not trusted");

			if (INODE_IS_WRITABLE(inode))
				return tpe_log_denied_action(file, method, "file is writable");

		}

	}

	return 0;
}

