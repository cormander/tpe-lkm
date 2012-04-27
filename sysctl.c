
#include "module.h"

int tpe_softmode = 0;
int tpe_trusted_gid = TPE_TRUSTED_GID;
int tpe_admin_gid = 0;
int tpe_dmz_gid = 0;
int tpe_strict = 1;
int tpe_check_file = 1;
int tpe_paranoid = 0;
char tpe_hardcoded_path[TPE_HARDCODED_PATH_LEN] = "";
int tpe_kill = 0;
int tpe_log = 1;
int tpe_log_max = 50;
int tpe_log_floodtime = LOG_FLOODTIME;
int tpe_log_floodburst = LOG_FLOODBURST;
int tpe_lock = 0;
int tpe_lsmod = 0;
int tpe_proc_kallsyms = 0;
int tpe_ps = 0;
int tpe_ps_gid = 0;

static ctl_table tpe_extras_table[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "lsmod",
		.data		= &tpe_lsmod,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "ps",
		.data		= &tpe_ps,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "ps_gid",
		.data		= &tpe_ps_gid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "proc_kallsyms",
		.data		= &tpe_proc_kallsyms,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{0}
};

static ctl_table tpe_table[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "softmode",
		.data		= &tpe_softmode,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "trusted_gid",
		.data		= &tpe_trusted_gid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "admin_gid",
		.data		= &tpe_admin_gid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "dmz_gid",
		.data		= &tpe_dmz_gid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "strict",
		.data		= &tpe_strict,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "check_file",
		.data		= &tpe_check_file,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "paranoid",
		.data		= &tpe_paranoid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
        {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
                .ctl_name       = CTL_UNNUMBERED,
#endif
                .procname       = "hardcoded_path",
                .data           = &tpe_hardcoded_path,
                .maxlen         = TPE_HARDCODED_PATH_LEN,
                .mode           = 0644,
                .proc_handler   = &proc_dostring,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
                .strategy       = &sysctl_string,
#endif
        },
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "kill",
		.data		= &tpe_kill,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "log",
		.data		= &tpe_log,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "log_max",
		.data		= &tpe_log_max,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "log_floodtime",
		.data		= &tpe_log_floodtime,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "log_floodburst",
		.data		= &tpe_log_floodburst,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "lock",
		.data		= &tpe_lock,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
		.procname	= "extras",
		.mode		= 0500,
		.child		= tpe_extras_table,
	},
	{0}
};

static ctl_table tpe_root_table[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
		.ctl_name	= CTL_UNNUMBERED,
#endif
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

