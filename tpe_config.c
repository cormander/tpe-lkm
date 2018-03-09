
#include "tpe.h"

int tpe_softmode = 0;
int tpe_xattr_soften = 1;
int tpe_trusted_gid = 0;
int tpe_trusted_invert = 0;
int tpe_admin_gid = 0;
int tpe_dmz_gid = 0;
int tpe_strict = 1;
int tpe_check_file = 1;
int tpe_group_writable = 1;
int tpe_paranoid = 0;
char tpe_trusted_apps[TPE_PATH_LEN] = "";
char tpe_hardcoded_path[TPE_PATH_LEN] = "";
int tpe_kill = 0;
int tpe_log = 1;
int tpe_log_verbose = 1;
int tpe_log_max = 50;
int tpe_log_floodtime = TPE_LOG_FLOODTIME;
int tpe_log_floodburst = TPE_LOG_FLOODBURST;
int tpe_lock = 0;

int tpe_extras_ignore_softmode = 0;
int tpe_extras_log = 1;
int tpe_ps = 0;
int tpe_ps_gid = 0;
int tpe_restrict_setuid = 0;
int tpe_lsmod = 1;
int tpe_proc_kallsyms = 1;
int tpe_harden_ptrace = 1;
int tpe_hide_uname = 0;

static struct ctl_table tpe_extras_table[] = {
	{
		.procname	= "ignore_softmode",
		.data		= &tpe_extras_ignore_softmode,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "log",
		.data		= &tpe_extras_log,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "ps",
		.data		= &tpe_ps,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "ps_gid",
		.data		= &tpe_ps_gid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "restrict_setuid",
		.data		= &tpe_restrict_setuid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "lsmod",
		.data		= &tpe_lsmod,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "proc_kallsyms",
		.data		= &tpe_proc_kallsyms,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "harden_ptrace",
		.data		= &tpe_harden_ptrace,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "hide_uname",
		.data		= &tpe_hide_uname,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{}
};

static struct ctl_table tpe_table[] = {
	{
		.procname	= "softmode",
		.data		= &tpe_softmode,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "xattr_soften",
		.data		= &tpe_xattr_soften,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "trusted_gid",
		.data		= &tpe_trusted_gid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "trusted_invert",
		.data		= &tpe_trusted_invert,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "admin_gid",
		.data		= &tpe_admin_gid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "dmz_gid",
		.data		= &tpe_dmz_gid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "strict",
		.data		= &tpe_strict,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "check_file",
		.data		= &tpe_check_file,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "group_writable",
		.data		= &tpe_group_writable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "paranoid",
		.data		= &tpe_paranoid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "trusted_apps",
		.data	 	= &tpe_trusted_apps,
		.maxlen		= TPE_PATH_LEN,
		.mode		= 0644,
		.proc_handler	= &proc_dostring,
	},
	{
		.procname	= "hardcoded_path",
		.data		= &tpe_hardcoded_path,
		.maxlen	 	= TPE_PATH_LEN,
		.mode	 	= 0644,
		.proc_handler	= &proc_dostring,
	},
	{
		.procname	= "kill",
		.data		= &tpe_kill,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "log",
		.data		= &tpe_log,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "log_verbose",
		.data		= &tpe_log_verbose,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "log_max",
		.data		= &tpe_log_max,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "log_floodtime",
		.data		= &tpe_log_floodtime,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "log_floodburst",
		.data		= &tpe_log_floodburst,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "lock",
		.data		= &tpe_lock,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "extras",
		.mode		= 0500,
		.child		= tpe_extras_table,
	},
	{}
};

static struct ctl_table tpe_root_table[] = {
	{
		.procname	= "tpe",
		.mode		= 0500,
		.child		= tpe_table,
	},
	{}
};

static struct ctl_table_header *tpe_table_header;

int __init tpe_config_init(void) {
	if (!(tpe_table_header = register_sysctl_table(tpe_root_table))) {
		printk(PKPRE "Unable to register sysctl table with the kernel\n");
		return -EFAULT;
	}

	return 0;
}

void __exit tpe_config_exit(void) {
	if (tpe_table_header)
		unregister_sysctl_table(tpe_table_header);
}

