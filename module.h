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

#include <asm/uaccess.h>
#include <asm/insn.h>

#define MODULE_NAME "tpe"
#define PKPRE "[" MODULE_NAME "] "

#define NEED_GPF_PROT 1

#define TPE_TRUSTED_GID 1337

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

int tpe_allow_file(const struct file *);
int tpe_allow(const char *);

void hijack_syscalls(void);
void undo_hijack_syscalls(void);

void symbol_info(struct kernsym *);

int find_symbol_address(struct kernsym *, const char *);

int malloc_init(void);

void *malloc(unsigned long size);
void malloc_free(void *buf);

#endif
