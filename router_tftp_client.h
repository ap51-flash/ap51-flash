/* SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2009-2019, Marek Lindner <mareklindner@neomailbox.ch>
 */

#ifndef __AP51_FLASH_ROUTER_TFTP_CLIENT_H__
#define __AP51_FLASH_ROUTER_TFTP_CLIENT_H__

struct node;

extern const struct router_type  a40;
extern const struct router_type  a42;
extern const struct router_type  a60;
extern const struct router_type  a62;
extern const struct router_type  d200;
extern const struct router_type  g200;
extern const struct router_type  mr1750;
extern const struct router_type  mr500;
extern const struct router_type  mr600;
extern const struct router_type  mr900;
extern const struct router_type  om2p;
extern const struct router_type  om5p;
extern const struct router_type  om5pac;
extern const struct router_type  om5pan;
extern const struct router_type  p60;
extern const struct router_type  pa1200;
extern const struct router_type  pa2200;
extern const struct router_type  zyxel;

void tftp_client_flash_time_set(struct node *node);
int tftp_client_flash_completed(struct node *node);

#endif /* __AP51_FLASH_ROUTER_TFTP_CLIENT_H__ */
