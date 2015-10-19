/***
 *
 * Copyright (C) 2012-2015 Open Mesh, Inc.
 *
 * The reproduction and distribution of this software without the written
 * consent of Open-Mesh, Inc. is prohibited by the United States Copyright
 * Act and international treaties.
 *
 ***/

#ifndef _FWCFG_H
#define _FWCFG_H

#include <stdint.h>
#include "types.h"

unsigned int fwupgrade_cfg_read_sizes(struct router_image *router_image,
				      struct file_info *file_info);

#endif /* _FWCFG_H */
