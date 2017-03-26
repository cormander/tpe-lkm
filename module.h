#ifndef TPE_H_INCLUDED
#define TPE_H_INCLUDED

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/mman.h>
#include <linux/binfmts.h>
#include <linux/version.h>
#include <linux/utsname.h>
#include <linux/kallsyms.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/sysctl.h>
#include <linux/err.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/ftrace.h>
#include <linux/uaccess.h>

#include <asm/uaccess.h>

#ifndef CONFIG_SECURITY
#error "This module requires CONFIG_SECURITY to be enabled"
#endif

#define MODULE_NAME "tpe"
#define PKPRE "[" MODULE_NAME "] "
#define MAX_FILE_LEN 256
#define TPE_PATH_LEN 1024

#ifdef CONFIG_X86_64
#define REGS_ARG1(r) r->di
#define REGS_ARG2(r) r->si
#define REGS_ARG3(r) r->dx
#else
#error "Arch not currently supported."
#endif

struct kernsym {
	void *addr;
	char *name;
	bool found;
	bool ftraced;
};

struct symhook {
	char *name;
	struct kernsym *sym;
	struct ftrace_ops *fops;
};

#define symhook_val(val) \
	{#val, &sym_##val, &fops_##val}

#define tpe_trace_handler(val) \
	static void notrace tpe_##val(unsigned long, unsigned long, \
		struct ftrace_ops *, struct pt_regs *); \
	struct kernsym sym_##val; \
	static struct ftrace_ops fops_##val __read_mostly = { \
		.func = tpe_##val, \
		.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY, \
	}; \
	static void notrace tpe_##val(unsigned long ip, unsigned long parent_ip, \
		struct ftrace_ops *fops, struct pt_regs *regs)

#define TPE_NOEXEC regs->ip = (unsigned long)tpe_donotexec

#define LOG_FLOODTIME 5
#define LOG_FLOODBURST 5

#define OP_JMP_SIZE 5

#define IN_ERR(x) (x < 0)

#define get_task_uid(task) task->cred->uid
#define get_task_parent(task) task->real_parent

#define tpe_d_path(file, buf, len) d_path(&file->f_path, buf, len);

#ifndef VM_EXECUTABLE
#define VM_EXECUTABLE VM_EXEC
#endif

#define get_inode(file) file->f_path.dentry->d_inode;
#define get_parent_inode(file) file->f_path.dentry->d_parent->d_inode;
#define exe_from_mm(mm, buf, len) tpe_d_path(mm->exe_file, buf, len)

#define UID_IS_TRUSTED(uid) \
	((uid == 0 && !tpe_paranoid) || \
	(!tpe_trusted_invert && tpe_trusted_gid && in_group_p(KGIDT_INIT(tpe_trusted_gid)) && !tpe_strict) || \
	(tpe_trusted_invert && !in_group_p(KGIDT_INIT(tpe_trusted_gid))))

#define INODE_IS_WRITABLE(inode) ((inode->i_mode & S_IWOTH) || (tpe_group_writable && inode->i_mode & S_IWGRP))
#define INODE_IS_TRUSTED(inode) \
        (__kuid_val(inode->i_uid) == 0 || \
        (tpe_admin_gid && __kgid_val(inode->i_gid) == tpe_admin_gid) || \
        (__kuid_val(inode->i_uid) == uid && !tpe_trusted_invert && tpe_trusted_gid && in_group_p(KGIDT_INIT(tpe_trusted_gid))))

int tpe_allow_file(const struct file *, const char *);
int tpe_allow(const char *, const char *);

void ftrace_syscalls(void);
void undo_ftrace_syscalls(void);

int tpe_config_init(void);
void tpe_config_exit(void);

/* sysctl entries for configuration */
extern int tpe_softmode;
extern int tpe_trusted_gid;
extern int tpe_trusted_invert;
extern int tpe_admin_gid;
extern int tpe_dmz_gid;
extern int tpe_strict;
extern int tpe_check_file;
extern int tpe_group_writable;
extern int tpe_paranoid;
extern char tpe_trusted_apps[];
extern char tpe_hardcoded_path[];
extern int tpe_kill;
extern int tpe_log;
extern int tpe_log_max;
extern int tpe_log_floodtime;
extern int tpe_log_floodburst;
extern int tpe_lsmod;
extern int tpe_proc_kallsyms;
extern int tpe_harden_ptrace;
extern int tpe_hide_uname;
extern int tpe_ps;
extern int tpe_ps_gid;
extern int tpe_restrict_setuid;

#endif
