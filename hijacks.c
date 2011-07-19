
#include "module.h"

#define OP_JMP_REL32	0xe9
#define OP_CALL_REL32	0xe8

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
	
	if (src_insn->opcode.bytes[0] == OP_CALL_REL32 ||
	    src_insn->opcode.bytes[0] == OP_JMP_REL32) {
			
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

// functions to set/unset write at the page that represents the given address
// this previously was code that disabled the write-protect bit of cr0, but
// this is much cleaner

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)

// TODO: this implementation just ignores the flag, not currently sure how to check
//	   if the page is already set to read/write

void set_addr_rw(unsigned long addr, bool *flag) {

	struct page *pg;

	pgprot_t prot;
	pg = virt_to_page(_addr);
	prot.pgprot = VM_READ | VM_WRITE;
	change_page_attr(pg, 1, prot);

}

void set_addr_ro(unsigned long addr, bool flag) {

	struct page *pg;

	pgprot_t prot;
	pg = virt_to_page(_addr);
	prot.pgprot = VM_READ;
	change_page_attr(pg, 1, prot);

}

#else

void set_addr_rw(unsigned long addr, bool *flag) {

	unsigned int level;
	pte_t *pte;

	*flag = true;

	pte = lookup_address(addr, &level);

	if (pte->pte & _PAGE_RW) *flag = false;
	else pte->pte |= _PAGE_RW;

}

void set_addr_ro(unsigned long addr, bool flag) {

	unsigned int level;
	pte_t *pte;

	// only set back to readonly if it was readonly before
	if (flag) {
		pte = lookup_address(addr, &level);

		pte->pte = pte->pte &~_PAGE_RW;
	}

}

#endif

int symbol_hijack(struct kernsym *sym, const char *symbol_name, unsigned long *code) {

	void *addr;
	int ret;
	unsigned long orig_addr;
	unsigned long dest_addr;
	unsigned long end_addr;
	u32 *poffset;
	struct insn insn;
	bool pte_ro;
	
	ret = find_symbol_address(sym, symbol_name);

	if (IS_ERR(ret))
		return ret;

	sym->new_addr = malloc(sym->size);

	if (sym->new_addr == NULL) {
		printk(PKPRE
			"Failed to allocate buffer of size %lu for %s\n",
			sym->size, sym->name);
		return -ENOMEM;
	}

	memset(sym->new_addr, 0, (size_t)sym->size);

	if (sym->size < OP_JMP_SIZE)
		return -EFAULT;
	
	orig_addr = (unsigned long)sym->addr;
	dest_addr = (unsigned long)sym->new_addr;
	
	end_addr = orig_addr + sym->size;
	while (end_addr > orig_addr && *(u8 *)(end_addr - 1) == '\0')
		--end_addr;
	
	if (orig_addr == end_addr) {
		printk(PKPRE
			"A spurious symbol \"%s\" (address: %p) seems to contain only zeros\n",
			sym->name,
			sym->addr);
		return -EILSEQ;
	}
	
	while (orig_addr < end_addr) {
		kernel_insn_init(&insn, (void *)orig_addr);
		insn_get_length(&insn);
		if (insn.length == 0) {
			printk(PKPRE
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

	set_addr_rw((unsigned long) sym->addr, &pte_ro);

	memcpy(&sym->orig_start_bytes[0], sym->addr, OP_JMP_SIZE);

	*(u8 *)sym->addr = OP_JMP_REL32;
	poffset = (u32 *)((unsigned long)sym->addr + 1);
	*poffset = CODE_OFFSET_FROM_ADDR((unsigned long)sym->addr, 
		OP_JMP_SIZE, (unsigned long)code);

	set_addr_ro((unsigned long) sym->addr, pte_ro);

	sym->hijacked = true;

	return ret;
}

void symbol_restore(struct kernsym *sym) {

	bool pte_ro;

	if (sym->new_addr)
		malloc_free(sym->new_addr);

	if (sym->hijacked) {

		set_addr_rw((unsigned long) sym->addr, &pte_ro);

		memcpy(sym->addr, &sym->orig_start_bytes[0], OP_JMP_SIZE);

		set_addr_ro((unsigned long) sym->addr, pte_ro);

		sym->hijacked = false;

	}

	return;
}

