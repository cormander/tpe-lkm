
#include "module.h"

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
	sym->run = sym->addr;

	return 0;
}

static int find_address_callback(struct kernsym *sym, const char *name, struct module *mod,
	unsigned long addr) {

	if (sym->found) {
		sym->end_addr = (unsigned long *)addr;
		return 1;
	}

	// this address was found. the next callback will be the address of the next symbol
	if (addr && (unsigned long) sym->addr == addr) {
		sym->name = malloc(strlen(name)+1);
		strncpy(sym->name, name, strlen(name)+1);
		sym->name_alloc = true;
		sym->found = true;
	}

	return 0;
}

int find_address_symbol(struct kernsym *sym, unsigned long addr) {

	int ret;

	sym->found = 0;
	sym->addr = (unsigned long *)addr;

	ret = kallsyms_on_each_symbol((void *)find_address_callback, sym);

	if (!ret)
		return -EFAULT;

	sym->size = sym->end_addr - sym->addr;
	sym->new_size = sym->size;
	sym->run = sym->addr;

	return 0;
}

#else

/*

We resort to using your /proc/kallsyms and System.map files since there really
is no other (easy) way. I could try to brute force the kernel memory range to
find the kallsyms_addresses table, and maybe one day I'll try that. But not
today.

*/

#define SYSTEM_MAP_PATH "/boot/System.map-"

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

	char buf[MAX_FILE_LEN];
	int i = 0;
	int ret = -EFAULT;
	char *p, *substr;
	struct file *f;

	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs (KERNEL_DS);

	f = filp_open(filename, O_RDONLY, 0);

	if (IS_ERR(f)) {
		ret = PTR_ERR(f);
		printk(PKPRE "Unable to open file %s\n", filename);
		goto out_nofilp;
	}

	memset(buf, 0x0, MAX_FILE_LEN);

	p = buf;

	while (vfs_read(f, p+i, 1, &f->f_pos) == 1) {

		if (p[i] == '\n' || i == (MAX_FILE_LEN-1)) {

			char *sys_string;

			// symbol was found, next symbols is the end address
			if (sym->found) {

				sys_string = kmalloc(MAX_FILE_LEN, GFP_KERNEL);

				if (sys_string == NULL) {
					ret = -ENOMEM;
					goto out;
				}

				memset(sys_string, 0, MAX_FILE_LEN);
				strncpy(sys_string, strsep(&p, " "), MAX_FILE_LEN);

				sym->end_addr = (unsigned long *) str2long(sys_string, NULL, 16);

				kfree(sys_string);

				sym->size = sym->end_addr - sym->addr;
				sym->new_size = sym->size;

				//printk(PKPRE "From %s, found %s end addr at %lx (total size %lu)\n", filename, sym->name, sym->end_addr, sym->size);

				ret = 0;

				goto out;
			}

			i = 0;

			substr = strstr(p, sym->name);

			if (!sym->found && substr != NULL && substr[-1] == ' ' && substr[strlen(sym->name)+1] == '\0') {

				sys_string = kmalloc(MAX_FILE_LEN, GFP_KERNEL);	

				if (sys_string == NULL) {
					ret = -ENOMEM;
					goto out;
				}

				memset(sys_string, 0, MAX_FILE_LEN);
				strncpy(sys_string, strsep(&p, " "), MAX_FILE_LEN);

				sym->addr = (unsigned long *) str2long(sys_string, NULL, 16);

				//printk(PKPRE "From %s, found %s start addr at %lx\n", filename, sym->name, sym->addr);

				kfree(sys_string);

				sym->found = true;
			}

			memset(buf, 0x0, MAX_FILE_LEN);
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

	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	struct new_utsname *uts = init_utsname();
	#else
	struct new_utsname *uts = utsname();
	#endif

	sym->name = symbol_name;

	ret = find_symbol_address_from_file(sym, "/proc/kallsyms");

	if (IN_ERR(ret)) {

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

	sym->run = sym->addr;

	out:

//	if (IN_ERR(ret))
//		printk(PKPRE "Failed to find symbol address for %s\n", symbol_name);

	return ret;
}

#endif

