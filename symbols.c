
#include "tpe.h"

/*

This file contains many different ways to locate a symbol's address based on name,
and tries to be the most efficient about it. It uses your System.map file as a last
resort.

*/

#define SYSTEM_MAP_PATH "/boot/System.map-"
#define MAX_LEN 256

// kernsym struct used for callbacks to kallsyms_on_each_symbol()

struct kernsym {
	unsigned long *addr;
	char *name;
	int found;
};

unsigned long (*kallsyms_lookup_name_addr)(const char *);
int kallsyms_lookup_name_notfound = 0;

// borrowed (copied) from simple_strtol() in vsprintf.c

unsigned long str2long(const char *cp, char **endp, unsigned int base) {
	if (*cp == '-')
		return -simple_strtoull(cp + 1, endp, base);
	return simple_strtoull(cp, endp, base);
}

// look up the symbol address from a file. used as the last method to try
// borrowed from memset's blog (with some needed modifications):
// http://memset.wordpress.com/2011/01/20/syscall-hijacking-dynamically-obtain-syscall-table-address-kernel-2-6-x/

unsigned long *find_symbol_address_from_file(const char *filename, const char *symbol_name) {

	char buf[MAX_LEN];
	int i = 0;
	char *p, *substr;
	struct file *f;
	unsigned long *addr = -EFAULT;

	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs (KERNEL_DS);

	f = filp_open(filename, O_RDONLY, 0);

	if (IS_ERR(f)) {
		addr = f;
		printk("Unable to open file %s\n", filename);
		goto out_nofilp;
	}

	memset(buf, 0x0, MAX_LEN);

	p = buf;

	while (vfs_read(f, p+i, 1, &f->f_pos) == 1) {

		if (p[i] == '\n' || i == (MAX_LEN-1)) {

			i = 0;

			substr = strstr(p, symbol_name);

			if (substr != NULL && substr[-1] == ' ' && substr[strlen(symbol_name)+1] == '\0') {

				char *sys_string;

				sys_string = kmalloc(MAX_LEN, GFP_KERNEL);	

				if (sys_string == NULL) {
					addr = -ENOMEM;
					goto out;
				}

				memset(sys_string, 0, MAX_LEN);
				strncpy(sys_string, strsep(&p, " "), MAX_LEN);

				addr = (unsigned long *) str2long(sys_string, NULL, 16);

				//printk("address of %s is %lx\n", symbol_name, addr);

				kfree(sys_string);

				break;
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

	return addr;
}

// look everywhere on the system that might contain the addresses we want

unsigned long *find_symbol_address_from_system(const char *symbol_name) {

	unsigned long *addr;
	char *filename;
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	struct new_utsname *uts = init_utsname();
	#else
	struct new_utsname *uts = utsname();
	#endif

	addr = find_symbol_address_from_file("/proc/kallsyms", symbol_name);

	if (IS_ERR(addr)) {

		filename = kmalloc(strlen(uts->release)+strlen(SYSTEM_MAP_PATH)+1, GFP_KERNEL);

		if (filename == NULL) {
			addr = -ENOMEM;
			goto out;
		}

		memset(filename, 0, strlen(SYSTEM_MAP_PATH)+strlen(uts->release)+1);

		strncpy(filename, SYSTEM_MAP_PATH, strlen(SYSTEM_MAP_PATH));
		strncat(filename, uts->release, strlen(uts->release));

		addr = find_symbol_address_from_file(filename, symbol_name);

		kfree(filename);
	}

	out:

	return addr;
}

// callback for find_symbol_address_brute

static int find_symbol_callback(struct kernsym *sym, const char *name, struct module *mod,
	unsigned long addr) {

	if (name && sym->name && !strcmp(name, sym->name)) {
		sym->addr = addr;
		return 1;
	}

	return 0;
}

// use the exported kallsyms_on_each_symbol()

unsigned long *find_symbol_address_brute(const char *symbol_name) {

	struct kernsym sym;
	int ret;

	sym.name = symbol_name;

	ret = kallsyms_on_each_symbol(find_symbol_callback, &sym);

	if (!ret || !sym.addr)
		return -EFAULT;

	return sym.addr;
}

// return the address of the given symbol. do everything we can to find it

unsigned long *find_symbol_address(const char *symbol_name) {

	unsigned long *addr;

	if (!kallsyms_lookup_name_addr && kallsyms_lookup_name_notfound == 0) {

		kallsyms_lookup_name_addr = find_symbol_address_brute("kallsyms_lookup_name");

		if (IS_ERR(kallsyms_lookup_name_addr))
			kallsyms_lookup_name_addr = find_symbol_address_from_system("kallsyms_lookup_name");

		if (IS_ERR(kallsyms_lookup_name_addr))
			kallsyms_lookup_name_notfound = 1;
	}

	if (kallsyms_lookup_name_notfound == 0)
		addr = (*kallsyms_lookup_name_addr)(symbol_name);

	if (addr)
		return addr;

	addr = find_symbol_address_brute(symbol_name);

	if (addr)
		return addr;

	// only decend into the filesystem if we _really_ have to
	return find_symbol_address_from_system(symbol_name);
}

// RHEL kernels don't compile with CONFIG_PRINTK_TIME. lame.

void up_printk_time(void) {

	int *printk_time_ptr;

	printk_time_ptr = find_symbol_address("printk_time");

	// no dice? oh well, no biggie
	if (IS_ERR(printk_time_ptr))
		return;

	if (*printk_time_ptr == 0) {
		*printk_time_ptr = 1;
		printk("Flipped printk_time to 1 because, well, I like it that way!\n");
	}

}

// callback for find_symbol_length

static int symbol_length_callback(struct kernsym *sym, const char *name, struct module *mod,
	unsigned long addr) {

	if (sym->found == 1) {
		sym->addr = addr;
		return 1;
	}

	// this symbol was found. the next callback will be the address of the next symbol
	if (name && sym->name && !strcmp(name, sym->name))
		sym->found = 1;

	return 0;
}

// get this symbol's length by finding the next one and subtracting the addresses

unsigned int *find_symbol_length(const char *symbol_name) {

	struct kernsym sym;
	unsigned long *addr;
	int ret;

	sym.name = symbol_name;
	sym.found = 0;

	ret = kallsyms_on_each_symbol(symbol_length_callback, &sym);

	addr = find_symbol_address(symbol_name);

	if (IS_ERR(addr) || !sym.addr)
		return -EFAULT;

	// sym.addr is the address of the next symbol
	return (unsigned int)sym.addr - (unsigned int)addr;
}

