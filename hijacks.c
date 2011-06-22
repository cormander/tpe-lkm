
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

void start_my_code(struct code_store *cs) {

	mutex_lock(&cs->lock);

	#if NEED_GPF_PROT
	GPF_DISABLE;
	#endif

	// Overwrite the bytes with instructions to return to our new function
	memcpy(cs->ptr, cs->jump_code, cs->size);

	#if NEED_GPF_PROT
	GPF_ENABLE;
	#endif

	mutex_unlock(&cs->lock);
}

void stop_my_code(struct code_store *cs) {

	mutex_lock(&cs->lock);

	#if NEED_GPF_PROT
	GPF_DISABLE;
	#endif

	// restore bytes to the original syscall address
	memcpy(cs->ptr, cs->orig_code, cs->size);

	#if NEED_GPF_PROT
	GPF_ENABLE;
	#endif

	mutex_unlock(&cs->lock);
}

void hijack_syscall(struct code_store *cs, const unsigned long code, const unsigned long addr) {

	cs->size = CODESIZE;

	cs->ptr = addr;

	memcpy(cs->jump_code, jump_code, cs->size);

	// tell the jump_code where we want to go
	*(unsigned long *)&cs->jump_code[CODEPOS] = (unsigned long)code;

	// save the bytes of the original syscall
	memcpy(cs->orig_code, cs->ptr, cs->size);

	// init the lock
	mutex_init(&cs->lock);

	// init the hijack
	start_my_code(cs);

}

