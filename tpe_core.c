/*

Trusted Path Execution (TPE) linux kernel module

*/

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

#define SYSTEM_MAP_PATH "/boot/System.map-"
#define MAX_LEN 256

#ifdef CONFIG_X86_32
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

// TODO: make the printks give more info (full path to file, pwd, gid, etc)

int tpe_allow_file(const struct file *file) {

	unsigned char *iname;
	struct inode *inode;
	uid_t uid;
	int ret = 0;

	// different versions of the kernels have a different task_struct
	// TODO: go look up when this actually changed. I just know that it did somewhere between
	//	2.6.18 and 2.6.32 :P
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	uid = current->uid;

	inode = file->f_dentry->d_parent->d_inode;
	iname = file->f_dentry->d_iname;
	#else
	uid = current_cred()->uid;

	inode = file->f_path.dentry->d_parent->d_inode;
	iname = file->f_path.dentry->d_iname;
	#endif

	// uid is not root and not trusted
	// file is not owned by root or owned by root and writable
	if (uid && !in_group_p(TPE_TRUSTED_GID) &&
		(inode->i_uid || (!inode->i_uid && ((inode->i_mode & S_IWGRP) || (inode->i_mode & S_IWOTH))))
	) {
		printk("Denied untrusted exec of %s by uid %d\n", iname, uid);
		ret = -EACCES;
	} else
	// a less restrictive TPE enforced even on trusted users
	if (uid &&
		((inode->i_uid && (inode->i_uid != uid)) ||
		(inode->i_mode & S_IWGRP) || (inode->i_mode & S_IWOTH))
	) {
		printk("Denied untrusted exec of %s by uid %d\n", iname, uid);
		ret = -EACCES;
	}

	return ret;
}

int tpe_allow(const char *name) {

	struct file *file;
	int ret;

	file = open_exec(name);

	if (IS_ERR(file))
		return file;

	ret = tpe_allow_file(file);

	fput(file);

	return ret;
}

unsigned long str2long(const char *cp, char **endp, unsigned int base) {
        if (*cp == '-')
                return -simple_strtoull(cp + 1, endp, base);
        return simple_strtoull(cp, endp, base);
}

int find_symbol_address(const char *symbol_name) {

	char buf[MAX_LEN];
	int i = 0;
	char *filename;
	char *p;
	struct file *f;
	struct new_utsname *uts = utsname();
	unsigned long addr;

	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs (KERNEL_DS);

	filename = kmalloc(strlen(uts->release)+strlen(SYSTEM_MAP_PATH)+1, GFP_KERNEL);

	if (filename == NULL) {
		addr = -ENOMEM;
		goto out_nofilp;
	}

	memset(filename, 0, strlen(SYSTEM_MAP_PATH)+strlen(uts->release)+1);

	strncpy(filename, SYSTEM_MAP_PATH, strlen(SYSTEM_MAP_PATH));
	strncat(filename, uts->release, strlen(uts->release));

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

			if ((strstr(p, symbol_name)) != NULL) {

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

	kfree(filename);

	return addr;
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

int init_tpe(void) {

	int ret;

	mutex_init(&gpf_lock);

	ret = hijack_syscalls();

	if (!IS_ERR(ret))
		printk("TPE added to kernel\n");

	return ret;
}

static void exit_tpe(void) {

	undo_hijack_syscalls();

	printk("TPE removed from kernel\n");

	return;
}

module_init(init_tpe);
module_exit(exit_tpe);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Trusted Path Execution (TPE) Module");

