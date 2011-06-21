
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/version.h>
#include <linux/mutex.h>
#include <linux/utsname.h>
#include <linux/kallsyms.h>
#include <asm/uaccess.h>

/*

 set NEED_GPF_PROT depending on your CPU and kernel version:

 * If it's set to zero when you need it, you will get "BUG: unable to handle
   kernel paging request", this module won't function, and you won't be able
   to remove it w/o rebooting.

 * If it's set when you don't, you'll hang or crash your system

*/

#define NEED_GPF_PROT 1

/*

  set WRAP_SYSCALLS to 1 if you want to wrap the syscalls we are hijacking,
  rather than just completly subvert them.

  NOTE: enabling this causes a rare "invalid opcode: 0000 [#1] SMP" BUG in the
  kernel, which renders your kernel unstable and requires you to hard-reboot.
  Only enable this if you're debugging that problem.

*/

#define WRAP_SYSCALLS 0

#define TPE_TRUSTED_GID 1337

typedef struct code_store {
	int size;
	char jump_code[16];
	char orig_code[16];
	long (*ptr)();
	struct mutex lock;
} code_store;

void start_my_code(struct code_store *cs);
void stop_my_code(struct code_store *cs);

int tpe_allow_file(const struct file *file);
int tpe_allow(const char *name);

int hijack_syscalls(void);
void undo_hijack_syscalls(void);

void up_printk_time(void);

