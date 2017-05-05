#ifndef SECRETS_H_INCLUDED
#define SECRETS_H_INCLUDED

#include <linux/module.h>
#include "../../fopskit.h"

#define PKPRE "docker-ksec: "
#define MAX_FILE_LEN 255

#define ksec_d_path(file, buf, len) d_path(&file->f_path, buf, len);
#define exe_from_mm(mm, buf, len) ksec_d_path(mm->exe_file, buf, len)

#endif
