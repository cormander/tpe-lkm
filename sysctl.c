
#include "module.h"

int tpe_enabled = 1;

static ctl_table tpe_table[] = {
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "enabled",
		.data		= &tpe_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{0}
};

static ctl_table tpe_root_table[] = {
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "tpe",
		.mode		= 0500,
		.child		= tpe_table,
	},
	{0}
};

static struct ctl_table_header *tpe_table_header;

int tpe_config_init(void) {
	if (!(tpe_table_header = register_sysctl_table(tpe_root_table)))
		return -EFAULT;

}

void tpe_config_exit(void) {

	if (tpe_table_header)
		unregister_sysctl_table(tpe_table_header);

}

