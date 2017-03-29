
#include "tpe.h"

unsigned long tpe_alert_wtime = 0;
unsigned long tpe_alert_fyet = 0;

/* lookup pathnames and log that an exec was denied */

int tpe_log_denied_action(const struct file *file, const char *method, const char *reason) {

	char filename[MAX_FILE_LEN], pfilename[MAX_FILE_LEN], *f, *pf;
	struct task_struct *parent, *task;
	int c = 0;

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

	parent = get_task_parent(current);

	f = tpe_d_path(file, filename, MAX_FILE_LEN);

	pf = exe_from_mm(parent->mm, pfilename, MAX_FILE_LEN);

	printk(PKPRE "%s untrusted %s of %s (uid:%d) by %s (uid:%d), parents: ",
		( tpe_softmode ? "Would deny" : "Denied" ),
		method,
		(!IS_ERR(f) ? f : "<d_path failed>"),
		get_task_uid(current),
		(!IS_ERR(pf) ? pf : "<d_path failed>"),
		get_task_uid(parent)
	);

	/* recursively walk the task's parent until we reach init
	   start from this task's grandparent, since this task and parent have already been printed */
	task = get_task_parent(parent);

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

		/* if trusted_apps is non-empty, allow exec if the task parent matches the full path */
		if (strlen(tpe_trusted_apps)) {
			p = path;
			strncpy(p, tpe_trusted_apps, TPE_PATH_LEN);

			f = exe_from_mm(get_task_parent(current)->mm, filename, MAX_FILE_LEN);

			while ((c = strsep(&p, ",")))
				if (!strcmp(c, f))
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

