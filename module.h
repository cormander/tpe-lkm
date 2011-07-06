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

#include <asm/uaccess.h>
#include <asm/insn.h>

#define MODULE_NAME "tpe"
#define PKPRE "[" MODULE_NAME "] "
#define MAX_FILE_LEN 256

#define NEED_GPF_PROT 1

#define TPE_TRUSTED_GID 1337

#define LOG_FLOODTIME 5
#define LOG_FLOODBURST 10

// extra kernel protections not related to TPE
#define TPE_EXTRA_PROT 0

#define OP_JMP_SIZE 5

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
	void *(*run)();
};

int symbol_hijack(struct kernsym *, const char *, unsigned long *);
void symbol_restore(struct kernsym *);

int tpe_allow_file(const struct file *, const char *);
int tpe_allow(const char *, const char *);

void hijack_syscalls(void);
void undo_hijack_syscalls(void);

void symbol_info(struct kernsym *);

int find_symbol_address(struct kernsym *, const char *);

int malloc_init(void);

void *malloc(unsigned long size);
void malloc_free(void *buf);

#endif
