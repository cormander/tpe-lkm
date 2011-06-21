
#include "tpe.h"

#define SYSTEM_MAP_PATH "/boot/System.map-"
#define MAX_LEN 256

unsigned long (*kallsyms_lookup_name_addr)(const char *);

unsigned long str2long(const char *cp, char **endp, unsigned int base) {
	if (*cp == '-')
		return -simple_strtoull(cp + 1, endp, base);
	return simple_strtoull(cp, endp, base);
}

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

unsigned long *find_symbol_address_from_system(const char *symbol_name) {

	unsigned long *addr;
	char *filename;
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	struct new_utsname *uts = init_utsname();
	#else
	struct new_utsname *uts = utsname();
	#endif

	addr = find_symbol_address_from_file("/proc/kallsyms", symbol_name);

	if (!addr || IS_ERR(addr)) {

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

unsigned long *find_symbol_address(const char *symbol_name) {

	unsigned long *addr;

	if (!kallsyms_lookup_name_addr) {
		kallsyms_lookup_name_addr = find_symbol_address_from_system("kallsyms_lookup_name");
		if (IS_ERR(kallsyms_lookup_name_addr))
			return -EFAULT;
	}

	addr = (*kallsyms_lookup_name_addr)(symbol_name);

	if (addr)
		return addr;

	return find_symbol_address_from_system(symbol_name);
}

void up_printk_time(void) {

	int *printk_time_ptr;

	printk_time_ptr = find_symbol_address("printk_time");

	// no dice? oh well, no biggie
	if (!printk_time_ptr || IS_ERR(printk_time_ptr))
		return;

	if (*printk_time_ptr == 0) {
		*printk_time_ptr = 1;
		printk("Flipped printk_time to 1 because, well, I like it that way!\n");
	}

}

