
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

struct mutex gpf_lock;

#define KEDR_OP_JMP_REL32	0xe9
#define KEDR_OP_CALL_REL32	0xe8

#ifdef CONFIG_X86_64
# define CODE_ADDR_FROM_OFFSET(insn_addr, insn_len, offset) \
	(void*)((s64)(insn_addr) + (s64)(insn_len) + (s64)(s32)(offset))

#else
# define CODE_ADDR_FROM_OFFSET(insn_addr, insn_len, offset) \
	(void*)((u32)(insn_addr) + (u32)(insn_len) + (u32)(offset))
#endif

#define CODE_OFFSET_FROM_ADDR(insn_addr, insn_len, dest_addr) \
	(u32)(dest_addr - (insn_addr + (u32)insn_len))

void copy_and_fixup_insn(struct insn *src_insn, void *dest,
	const struct kernsym *func) {

	u32 *to_fixup;
	unsigned long addr;
	BUG_ON(src_insn->length == 0);
	
	memcpy((void *)dest, (const void *)src_insn->kaddr, 
		src_insn->length);
	
	if (src_insn->opcode.bytes[0] == KEDR_OP_CALL_REL32 ||
	    src_insn->opcode.bytes[0] == KEDR_OP_JMP_REL32) {
			
		addr = (unsigned long)CODE_ADDR_FROM_OFFSET(
			src_insn->kaddr,
			src_insn->length, 
			src_insn->immediate.value);
		
		if (addr >= (unsigned long)func->addr && 
		    addr < (unsigned long)func->addr + func->size)
			return;
		
		to_fixup = (u32 *)((unsigned long)dest + 
			insn_offset_immediate(src_insn));
		*to_fixup = CODE_OFFSET_FROM_ADDR(dest, src_insn->length,
			(void *)addr);
		return;
	}

#ifdef CONFIG_X86_64
	if (!insn_rip_relative(src_insn))
		return;
		
	addr = (unsigned long)CODE_ADDR_FROM_OFFSET(
		src_insn->kaddr,
		src_insn->length, 
		src_insn->displacement.value);
	
	if (addr >= (unsigned long)func->addr && 
	    addr < (unsigned long)func->addr + func->size)
		return;
	
	to_fixup = (u32 *)((unsigned long)dest + 
		insn_offset_displacement(src_insn));
	*to_fixup = CODE_OFFSET_FROM_ADDR(dest, src_insn->length,
		(void *)addr);
#endif
	return;
}

int symbol_hijack(struct kernsym *sym, const char *symbol_name, unsigned long *code) {

	void *addr;
	int ret;
	unsigned long orig_addr;
	unsigned long dest_addr;
	unsigned long end_addr;
	u32 *poffset;
	struct insn insn;
	
	ret = find_symbol_address(sym, symbol_name);

	if (IS_ERR(ret))
		return ret;

	sym->new_addr = malloc(sym->size);

	if (sym->new_addr == NULL) {
		printk(KERN_ERR "[tpe] "
			"Failed to allocate buffer of size %lu for %s\n",
			sym->size, sym->name);
		return -ENOMEM;
	}

	memset(sym->new_addr, 0, (size_t)sym->size);

	if (sym->size < KEDR_REL_JMP_SIZE)
		return -EFAULT;
	
	orig_addr = (unsigned long)sym->addr;
	dest_addr = (unsigned long)sym->new_addr;
	
	end_addr = orig_addr + sym->size;
	while (end_addr > orig_addr && *(u8 *)(end_addr - 1) == '\0')
		--end_addr;
	
	if (orig_addr == end_addr) {
		printk(KERN_ERR "[tpe] "
			"A spurious symbol \"%s\" (address: %p) seems to contain only zeros\n",
			sym->name,
			sym->addr);
		return -EILSEQ;
	}
	
	while (orig_addr < end_addr) {
		kernel_insn_init(&insn, (void *)orig_addr);
		insn_get_length(&insn);
		if (insn.length == 0) {
			printk(KERN_ERR "[tpe] "
				"Failed to decode instruction at %p (%s+0x%lx)\n",
				(const void *)orig_addr,
				sym->name,
				orig_addr - (unsigned long)sym->addr);
			return -EILSEQ;
		}
		
		copy_and_fixup_insn(&insn, (void *)dest_addr, sym);
		
		orig_addr += insn.length;
		dest_addr += insn.length;
	}
	
	sym->new_size = dest_addr - (unsigned long)sym->new_addr;

	sym->run = (unsigned long) sym->new_addr;

	GPF_DISABLE;

	memcpy(&sym->orig_start_bytes[0], sym->addr, KEDR_REL_JMP_SIZE);

	*(u8 *)sym->addr = KEDR_OP_JMP_REL32;
	poffset = (u32 *)((unsigned long)sym->addr + 1);
	*poffset = CODE_OFFSET_FROM_ADDR((unsigned long)sym->addr, 
		KEDR_REL_JMP_SIZE, (unsigned long)code);

	GPF_ENABLE;

	sym->hijacked = true;

	return ret;
}

void symbol_restore(struct kernsym *sym) {

	if (sym->new_addr)
		malloc_free(sym->new_addr);

	if (sym->hijacked) {

		GPF_DISABLE;

		memcpy(sym->addr, &sym->orig_start_bytes[0], KEDR_REL_JMP_SIZE);

		GPF_ENABLE;

		sym->hijacked = false;

	}

	return;
}

