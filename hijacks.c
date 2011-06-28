
#include "tpe.h"

// these are to prevent "general protection fault"s from occurring when we
// write to kernel memory
#define GPF_DISABLE \
	 mutex_lock(&gpf_lock); \
	 write_cr0 (read_cr0 () & (~ 0x10000)); \
	 mutex_unlock(&gpf_lock)

#define GPF_ENABLE \
	 mutex_lock(&gpf_lock); \
	 write_cr0 (read_cr0 () | 0x10000); \
	 mutex_unlock(&gpf_lock)

#ifdef CONFIG_X86_32
#error "This module does not currently work on 32bit systems. There is a problem with the asm jump code"
#define CODESIZE 7
#define CODEPOS 1
const char jump_code[] =
	 "\xb8\x00\x00\x00\x00"  // movl $0, %eax
	 "\xff\xe0"		// jump *%eax
	 ;
#else
#define CODESIZE 12
#define CODEPOS 2
const char jump_code[] =
	 "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00"      // movq $0, %rax
	 "\xff\xe0"					   // jump *%rax
	 ;
#endif

struct mutex gpf_lock;

// the meat of hijacking the given symbol

void start_my_code(struct kernsym *sym) {

	mutex_lock(&sym->lock);

	#if NEED_GPF_PROT
	GPF_DISABLE;
	#endif

	// Overwrite the bytes with instructions to return to our new function
	memcpy(sym->ptr, sym->jump_code, CODESIZE);

	#if NEED_GPF_PROT
	GPF_ENABLE;
	#endif

	mutex_unlock(&sym->lock);
}

// restore the given symbol to what it was before the hijacking

void stop_my_code(struct kernsym *sym) {

	mutex_lock(&sym->lock);

	#if NEED_GPF_PROT
	GPF_DISABLE;
	#endif

	// restore bytes to the original syscall address
	memcpy(sym->ptr, sym->orig_code, CODESIZE);

	#if NEED_GPF_PROT
	GPF_ENABLE;
	#endif

	mutex_unlock(&sym->lock);
}

// initialize the kernsym structure and pass it along to start_my_code()

void hijack_syscall(struct kernsym *sym, unsigned long *code) {

	sym->ptr = sym->addr;

	memcpy(sym->jump_code, jump_code, CODESIZE);

	// tell the jump_code where we want to go
	*(unsigned long *)&sym->jump_code[CODEPOS] = (unsigned long)code;

	// save the bytes of the original syscall
	memcpy(sym->orig_code, sym->ptr, CODESIZE);

	// init the lock
	mutex_init(&sym->lock);

	// init the hijack
	start_my_code(sym);

}

