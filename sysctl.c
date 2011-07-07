
#include "module.h"

int tpe_enabled = 1;
int tpe_trusted_gid = TPE_TRUSTED_GID;
int tpe_paranoid = 0;
int tpe_log = 1;
int tpe_log_floodtime = LOG_FLOODTIME;
int tpe_log_floodburst = LOG_FLOODBURST;
int tpe_dmesg = 0;
int tpe_lsmod = 0;
int tpe_proc_kallsyms = 0;
#ifndef HAVE_MODULES_DISABLED
int tpe_modules_disabled = 0;
#endif

static ctl_table tpe_extras_table[] = {
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "dmesg",
		.data		= &tpe_dmesg,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "lsmod",
		.data		= &tpe_lsmod,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "proc_kallsyms",
		.data		= &tpe_proc_kallsyms,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#ifndef HAVE_MODULES_DISABLED
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "modules_disabled",
		.data		= &tpe_modules_disabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#endif
	{0}
};

static ctl_table tpe_table[] = {
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "enabled",
		.data		= &tpe_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "trusted_gid",
		.data		= &tpe_trusted_gid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "paranoid",
		.data		= &tpe_paranoid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "log",
		.data		= &tpe_log,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "log_floodtime",
		.data		= &tpe_log_floodtime,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "log_floodburst",
		.data		= &tpe_log_floodburst,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "extras",
		.mode		= 0500,
		.child		= tpe_extras_table,
	},
	{0}
};

static ctl_table tpe_root_table[] = {
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= MODULE_NAME,
		.mode		= 0500,
		.child		= tpe_table,
	},
	{0}
};

static struct ctl_table_header *tpe_table_header;

int tpe_config_init(void) {
	if (!(tpe_table_header = register_sysctl_table(tpe_root_table
// TODO: verify this version number
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19) 
		, 0
#endif
		))) {
		printk(PKPRE "Unable to register sysctl table with the kernel\n");
		return -EFAULT;
	}

	return 0;
}

void tpe_config_exit(void) {

	if (tpe_table_header)
		unregister_sysctl_table(tpe_table_header);

}

