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

#include <asm/uaccess.h>
#include <asm/insn.h>

#ifndef CONFIG_SECURITY
#error "This module requires CONFIG_SECURITY to be enabled"
#endif

#define MODULE_NAME "tpe"
#define PKPRE "[" MODULE_NAME "] "
#define MAX_FILE_LEN 256
#define TPE_HARDCODED_PATH_LEN 1024

#define TPE_TRUSTED_GID 1337

#define LOG_FLOODTIME 5
#define LOG_FLOODBURST 5

#define OP_JMP_SIZE 5

#define IN_ERR(x) (x < 0)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
#define get_task_uid(task) task->uid
#define get_task_parent(task) task->parent
#else
#define get_task_uid(task) task->cred->uid
#define get_task_parent(task) task->real_parent
#endif

// d_path changed argument types. lame

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
#define tpe_d_path(file, buf, len) d_path(file->f_dentry, file->f_vfsmnt, buf, len);
#else
#define tpe_d_path(file, buf, len) d_path(&file->f_path, buf, len);
#endif

struct kernsym {
	void *addr; // orig addr
	void *end_addr;
	unsigned long size;
	const char *name;
	u8 orig_start_bytes[OP_JMP_SIZE];
	void *new_addr;
	unsigned long new_size;
	bool found;
	bool hijacked;
	void *run;
};

int symbol_hijack(struct kernsym *, const char *, unsigned long *);
void symbol_restore(struct kernsym *);

int tpe_allow_file(const struct file *, const char *);
int tpe_allow(const char *, const char *);
void tpe_sys_kill(int, int);

void hijack_syscalls(void);
void undo_hijack_syscalls(void);

void symbol_info(struct kernsym *);

int find_symbol_address(struct kernsym *, const char *);

int malloc_init(void);

void *malloc(unsigned long size);
void malloc_free(void *buf);

int tpe_config_init(void);
void tpe_config_exit(void);

// sysctl entries for configuration
extern int tpe_softmode;
extern int tpe_trusted_gid;
extern int tpe_admin_gid;
extern int tpe_dmz_gid;
extern int tpe_strict;
extern int tpe_check_file;
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

#endif
