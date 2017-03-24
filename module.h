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
#define TPE_HARDCODED_PATH_LEN 1024

#define LOG_FLOODTIME 5
#define LOG_FLOODBURST 5

#define OP_JMP_SIZE 5

#define IN_ERR(x) (x < 0)

#define get_task_uid(task) task->cred->uid
#define get_task_parent(task) task->real_parent

// d_path changed argument types. lame

#define tpe_d_path(file, buf, len) d_path(&file->f_path, buf, len);

#ifndef VM_EXECUTABLE
#define VM_EXECUTABLE VM_EXEC
#endif

#define UID_IS_TRUSTED(uid) \
	((uid == 0 && !tpe_paranoid) || \
	(!tpe_trusted_invert && tpe_trusted_gid && in_group_p(KGIDT_INIT(tpe_trusted_gid)) && !tpe_strict) || \
	(tpe_trusted_invert && !in_group_p(KGIDT_INIT(tpe_trusted_gid))))

struct kernsym {
	void *addr;
	char *name;
	bool name_alloc; // whether or not we alloc'd memory for char *name
	bool found;
	bool ftraced;
};

int tpe_allow_file(const struct file *, const char *);
int tpe_allow(const char *, const char *);

void ftrace_syscalls(void);
void undo_ftrace_syscalls(void);

void symbol_info(struct kernsym *);

int find_symbol_address(struct kernsym *, const char *);

int kernfunc_init(void);

void *malloc(unsigned long size);
void malloc_free(void *buf);

int tpe_config_init(void);
void tpe_config_exit(void);

// sysctl entries for configuration
extern int tpe_softmode;
extern int tpe_trusted_gid;
extern int tpe_trusted_invert;
extern int tpe_admin_gid;
extern int tpe_dmz_gid;
extern int tpe_strict;
extern int tpe_check_file;
extern int tpe_group_writable;
extern int tpe_paranoid;
extern char tpe_hardcoded_path[];
extern int tpe_kill;
extern int tpe_log;
extern int tpe_log_max;
extern int tpe_log_floodtime;
extern int tpe_log_floodburst;
extern int tpe_lock;
extern int tpe_lsmod;
extern int tpe_proc_kallsyms;
extern int tpe_ps;
extern int tpe_ps_gid;
extern int tpe_harden_symlink;
extern int tpe_harden_hardlinks;
extern int tpe_restrict_setuid;

#endif
