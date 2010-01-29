/*
 * Copyright (C) Open Mesh, Inc., Marek Lindner
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 3 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

static struct device_info flash_8mb_info = {
	.full_size = 0x00800000,
	.flash_size = 0x007A0000,
	.freememlo = 0x80041000, /* %{FREEMEMLO} provokes errors on the meraki mini */
	.flash_addr = 0xa8030000,
	.kernel_part_size = 0x00100000,
	.kernel_load_addr = 0x80041000,
	.options = ROOTFS_RESIZE | SET_FLASH_ADDR,
};

static struct device_info flash_4mb_info = {
	.full_size = 0x00400000,
	.flash_size = 0x003A0000,
	.freememlo = 0, /* we can use %{FREEMEMLO} instead */
	.flash_addr = 0xbfc30000,
	.kernel_part_size = 0x000e0000,
	.kernel_load_addr = 0x80041000,
	.options = FREEMEMLO,
};
