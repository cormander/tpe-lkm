
#include "tpe.h"

// for debugging

void symbol_info(struct kernsym *sym) {

	printk("[tpe] name => %s, addr => %lx, end_addr => %lx, size => %d, new_addr => %lx, new_size => %d, found => %d\n",
		sym->name,
		sym->addr,
		sym->end_addr,
		sym->size,
		sym->new_addr,
		sym->new_size,
		sym->found);
}

// use the newer, cleaner code of post 2.6.29
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)

// callback for find_symbol_address

static int find_symbol_callback(struct kernsym *sym, const char *name, struct module *mod,
	unsigned long addr) {

	if (sym->found) {
		sym->end_addr = (unsigned long *)addr;
		return 1;
	}

	// this symbol was found. the next callback will be the address of the next symbol
	if (name && sym->name && !strcmp(name, sym->name)) {
		sym->addr = (unsigned long *)addr;
		sym->found = true;
	}

	return 0;
}

// find this symbol

int find_symbol_address(struct kernsym *sym, const char *symbol_name) {

	int ret;

	sym->name = (char *)symbol_name;
	sym->found = 0;

	ret = kallsyms_on_each_symbol((void *)find_symbol_callback, sym);

	if (!ret)
		return -EFAULT;

	sym->size = sym->end_addr - sym->addr;
	sym->new_size = sym->size;
	sym->run = (unsigned long) sym->addr;

	return 0;
}

#else

/*

We resort to useing your /proc/kallsyms and System.map files since there really
is no other (easy) way. I could try to brute force the kernel memory range to
find the kallsyms_addresses table, and maybe one day I'll try that. But not
today.

*/

#define SYSTEM_MAP_PATH "/boot/System.map-"
#define MAX_LEN 256

// borrowed (copied) from simple_strtol() in vsprintf.c

unsigned long str2long(const char *cp, char **endp, unsigned int base) {
	if (*cp == '-')
		return -simple_strtoull(cp + 1, endp, base);
	return simple_strtoull(cp, endp, base);
}

// look up the symbol address from a file. used as the last method to try
// borrowed from memset's blog (with some needed modifications):
// http://memset.wordpress.com/2011/01/20/syscall-hijacking-dynamically-obtain-syscall-table-address-kernel-2-6-x/

int find_symbol_address_from_file(struct kernsym *sym, const char *filename) {

	char buf[MAX_LEN];
	int i = 0;
	int ret = -EFAULT;
	char *p, *substr;
	struct file *f;

	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs (KERNEL_DS);

	f = filp_open(filename, O_RDONLY, 0);

	if (IS_ERR(f)) {
		ret = f;
		printk("Unable to open file %s\n", filename);
		goto out_nofilp;
	}

	memset(buf, 0x0, MAX_LEN);

	p = buf;

	while (vfs_read(f, p+i, 1, &f->f_pos) == 1) {

		if (p[i] == '\n' || i == (MAX_LEN-1)) {

			char *sys_string;

			// symbol was found, next symbols is the end address
			if (sym->found) {

				sys_string = kmalloc(MAX_LEN, GFP_KERNEL);

				if (sys_string == NULL) {
					ret = -ENOMEM;
					goto out;
				}

				memset(sys_string, 0, MAX_LEN);
				strncpy(sys_string, strsep(&p, " "), MAX_LEN);

				sym->end_addr = (unsigned long *) str2long(sys_string, NULL, 16);

				kfree(sys_string);

				sym->size = sym->end_addr - sym->addr;
				sym->new_size = sym->size;

				//printk("From %s, found %s end addr at %lx (total size %lu)\n", filename, sym->name, sym->end_addr, sym->size);

				ret = 0;

				goto out;
			}

			i = 0;

			substr = strstr(p, sym->name);

			if (!sym->found && substr != NULL && substr[-1] == ' ' && substr[strlen(sym->name)+1] == '\0') {

				sys_string = kmalloc(MAX_LEN, GFP_KERNEL);	

				if (sys_string == NULL) {
					ret = -ENOMEM;
					goto out;
				}

				memset(sys_string, 0, MAX_LEN);
				strncpy(sys_string, strsep(&p, " "), MAX_LEN);

				sym->addr = (unsigned long *) str2long(sys_string, NULL, 16);

				//printk("From %s, found %s start addr at %lx\n", filename, sym->name, sym->addr);

				kfree(sys_string);

				sym->found = true;
			}

			memset(buf, 0x0, MAX_LEN);
			continue;
		}

		i++;

	}

	out:

	filp_close(f, 0);

	out_nofilp:

	set_fs(oldfs);

	return ret;
}

// look everywhere on the system that might contain the addresses we want

int find_symbol_address(struct kernsym *sym, const char *symbol_name) {

	char *filename;
	int ret;
	// TODO: figure out when this related commit was
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	struct new_utsname *uts = init_utsname();
	#else
	struct new_utsname *uts = utsname();
	#endif

	sym->name = symbol_name;

	ret = find_symbol_address_from_file(sym, "/proc/kallsyms");

	if (IS_ERR(ret)) {

		filename = kmalloc(strlen(uts->release)+strlen(SYSTEM_MAP_PATH)+1, GFP_KERNEL);

		if (filename == NULL) {
			ret = -ENOMEM;
			goto out;
		}

		memset(filename, 0, strlen(SYSTEM_MAP_PATH)+strlen(uts->release)+1);

		strncpy(filename, SYSTEM_MAP_PATH, strlen(SYSTEM_MAP_PATH));
		strncat(filename, uts->release, strlen(uts->release));

		ret = find_symbol_address_from_file(sym, filename);

		kfree(filename);
	}

	sym->run = (unsigned long) sym->addr;

	out:

//	if (IS_ERR(ret))
//		printk("Failed to find symbol address for %s\n", symbol_name);

	return ret;
}

#endif

#ifdef CONFIG_X86_32

/*

The code below is pure evil. It brute forces the memory range of the kernel to
find the kallsyms_addresses table. I can't believe how easy it was to write. I
mean, c'mon. Even making the table a linked list would make it harder to find!

Anyway. Currently only works on 32bit. 64bit has a different memory range, and
it's not so obvious to me at the moment what it is. I'll figure it out
eventually.

*/

#define START_MEM   0xc0000000
#define END_MEM     0xd0000000

int find_kallsyms_addresses(void) {

	unsigned long **ksyms_table;
	unsigned long i = START_MEM;

	unsigned long kallsyms_addresses_start;
	unsigned long kallsyms_addresses_end;
	int kallsyms_addresses_num = 0;

	int j;
	int ret = -EFAULT;

	write_cr0 (read_cr0 () & (~ 0x10000)); // TODO: verify that this is needed

	// scan all of kernel memory looking for a giant lump of pointers to the kernel memory range

	while ( i < END_MEM ) {

		unsigned long z = i;
		unsigned long *kallsyms_num_syms_p;

		ksyms_table = (unsigned long **)z;

		for (j = 0; ksyms_table[0] > START_MEM && ksyms_table[0] < END_MEM; j++) {

			z += sizeof(unsigned long);

			ksyms_table = (unsigned long **)z;

		}

		kallsyms_num_syms_p = z;

		// assume AT LEAST 100 entries
		// if the symbol after this one is a pointer to a number that's == j
		// and this is the biggest table of unsigned longs
		// it's what we want (if nothing else beats it out)
		if (j > 100 && j == *kallsyms_num_syms_p && j > kallsyms_addresses_num) {

			// if we got here, "i" should point to kallsyms_addresses, and "z" point to the end of the table (where kallsyms_num_syms is)

			kallsyms_addresses_start = i;
			kallsyms_addresses_end = z;
			kallsyms_addresses_num = j;

			//printk("Possible kallsyms_addresses table at %lx (size = %d)\n", kallsyms_addresses_start, kallsyms_addresses_num);

		}

		i += sizeof(void *);
	}

	if (kallsyms_addresses_start) {

		unsigned long *kallsyms_num_syms_p = kallsyms_addresses_end;

		printk("%lx => kallsyms_addresses\n", kallsyms_addresses_start);

		printk("%lx => kallsyms_num_syms (j = %d, size = %lu)\n", kallsyms_addresses_end, kallsyms_addresses_num, *kallsyms_num_syms_p);

		printk("%lx => kallsyms_names\n", kallsyms_addresses_end+sizeof(unsigned long));

		// TODO: figure this one out. I don't quite have the offset right
		//printk("And %lx should be kallsyms_markers\n", (z+sizeof(unsigned long)) + (j*sizeof(u8)));
		// TODO: kallsyms_token_table and kallsyms_token_index come right after
		//       once we have those, we can implement our own kallsyms_on_each_symbol function
		//       for the systems that don't have it ;)

		ret = 0; // success

	}

	return ret;

}

#endif

