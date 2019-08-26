/* SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: Sven Eckelmann <sven@narfation.org>
 */

#ifndef __AP51_FLASH_FWCFG_H__
#define __AP51_FLASH_FWCFG_H__

struct file_info;
struct router_image;

unsigned int fwupgrade_cfg_read_sizes(struct router_image *router_image,
				      const struct file_info *file_info);

#endif /* __AP51_FLASH_FWCFG_H__ */
