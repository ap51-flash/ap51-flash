/*
 * Copyright (C) Marek Lindner
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
 *
 * SPDX-License-Identifier: GPL-3.0+
 * License-Filename: LICENSES/preferred/GPL-3.0
 */

#include "router_images.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "ap51-flash.h"
#include "ap51-flash-res.h"
#include "compat.h"
#include "flash.h"
#include "fwcfg.h"
#include "list.h"
#include "proto.h"
#include "router_types.h"

static const char fwupgradecfg[] = "fwupgrade.cfg";
static const char fwupgradecfgsig[] = "fwupgrade.cfg.sig";

#define TFTP_PAYLOAD_SIZE 512

#if defined(EMBED_UBOOT) && defined(LINUX)
extern unsigned long _binary_img_uboot_start;
extern unsigned long _binary_img_uboot_end;
extern unsigned long _binary_img_uboot_size;
#endif

#if defined(EMBED_UBNT) && defined(LINUX)
extern unsigned long _binary_img_ubnt_start;
extern unsigned long _binary_img_ubnt_end;
extern unsigned long _binary_img_ubnt_size;
#endif

#if defined(EMBED_CI) && defined(LINUX)
extern unsigned long _binary_img_ci_start;
extern unsigned long _binary_img_ci_end;
extern unsigned long _binary_img_ci_size;
#endif

#if defined(EMBED_CE) && defined(LINUX)
extern unsigned long _binary_img_ce_start;
extern unsigned long _binary_img_ce_end;
extern unsigned long _binary_img_ce_size;
#endif

#if defined(EMBED_ZYXEL) && defined(LINUX)
extern unsigned long _binary_img_zyxel_start;
extern unsigned long _binary_img_zyxel_end;
extern unsigned long _binary_img_zyxel_size;
#endif

struct router_info *router_image_router_get(struct router_image *router_image,
					    const char *router_desc)
{
	struct list *list;
	struct router_info *router_info = NULL, *router_info_tmp;

	slist_for_each (list, router_image->router_list) {
		router_info_tmp = (struct router_info *)list->data;

		if (strcasecmp(router_info_tmp->router_name, router_desc) != 0)
			continue;

		router_info = router_info_tmp;
		break;
	}

	return router_info;
}

static struct router_info *router_image_router_add(struct router_image *router_image,
						   const char *router_desc)
{
	struct list *list;
	struct router_info *router_info;

	router_info = router_image_router_get(router_image, router_desc);
	if (router_info)
		goto out;

	router_info = malloc(sizeof(struct router_info));
	if (!router_info)
		goto out;

	list = malloc(sizeof(struct list));
	if (!list)
		goto free_router;

	memset(list, 0, sizeof(struct list));
	memset(router_info, 0, sizeof(struct router_info));
	strncpy(router_info->router_name, router_desc, sizeof(router_info->router_name));
	router_info->router_name[sizeof(router_info->router_name) - 1] = '\0';
	router_info->file_size = 0;
	list->data = router_info;
	list->next = NULL;
	list_prepend(&router_image->router_list, list);
	goto out;

free_router:
	free(router_info);
	router_info = NULL;
out:
	return router_info;
}

static struct file_info *_router_image_get_file(struct list *file_list,
						const char *file_name)
{
	struct list *list;
	struct file_info *file_info = NULL, *file_info_tmp;

	slist_for_each (list, file_list) {
		file_info_tmp = (struct file_info *)list->data;

		if (strcasecmp(file_info_tmp->file_name, file_name) != 0)
			continue;

		file_info = file_info_tmp;
		break;
	}

	return file_info;
}

struct file_info *router_image_get_file(struct router_type *router_type,
					const char *file_name)
{
	struct file_info *file_info = NULL;
	char file_name_buff[FILE_NAME_MAX_LENGTH];

	if (strcmp(file_name, fwupgradecfg) == 0) {
		snprintf(file_name_buff, FILE_NAME_MAX_LENGTH - 1, "%s-%s",
			 file_name,
			 router_type->image_desc ? router_type->image_desc : router_type->desc);
		file_info = _router_image_get_file(router_type->image->file_list,
						   file_name_buff);
	}

	if (strcmp(file_name, fwupgradecfgsig) == 0) {
		snprintf(file_name_buff, FILE_NAME_MAX_LENGTH - 1, "%s-%s.sig",
			 fwupgradecfg,
			 router_type->image_desc ? router_type->image_desc : router_type->desc);
		file_info = _router_image_get_file(router_type->image->file_list,
						   file_name_buff);
	}

	if (!file_info)
		file_info = _router_image_get_file(router_type->image->file_list,
						   file_name);

	return file_info;
}

static struct file_info *_router_image_add_file(struct router_image *router_image,
						const char *file_name)
{
	struct list *list;
	struct file_info *file_info;

	file_info = _router_image_get_file(router_image->file_list, file_name);
	if (file_info)
		goto out;

	file_info = malloc(sizeof(struct file_info));
	if (!file_info)
		goto out;

	list = malloc(sizeof(struct list));
	if (!list)
		goto free_node;

	memset(list, 0, sizeof(struct list));
	memset(file_info, 0, sizeof(struct file_info));
	strncpy(file_info->file_name, file_name, sizeof(file_info->file_name));
	file_info->file_name[sizeof(file_info->file_name) - 1] = '\0';
	list->data = file_info;
	list->next = NULL;
	list_prepend(&router_image->file_list, list);
	goto out;

free_node:
	free(file_info);
	file_info = NULL;
out:
	return file_info;
}

static int router_image_add_file(struct router_image *router_image,
				 const char *file_name, int file_size,
				 int file_fsize, int file_offset)
{
	struct file_info *file_info;

	file_info = _router_image_add_file(router_image, file_name);
	if (!file_info)
		return 1;

	file_info->file_size = file_size;
	file_info->file_fsize = file_fsize;
	file_info->file_offset = file_offset;
	return 0;
}

unsigned int router_image_get_size(struct router_type *router_type)
{
	const char *router_desc;
	const struct router_info *router_info;

	if (router_type->image_desc)
		router_desc = router_type->image_desc;
	else
		router_desc = router_type->desc;

	router_info = router_image_router_get(router_type->image, router_desc);
	if (router_info && router_info->file_size)
		return router_info->file_size;

	return router_type->image->file_size;
}

struct file_info *router_image_get_file_info(struct router_image *router_image,
					     const char *file_name)
{
	struct file_info *file_info;

	file_info = _router_image_get_file(router_image->file_list, file_name);
	if (!file_info)
		return NULL;

	return file_info;
}

static void router_image_set_size(struct router_image *router_image,
				  const char *router_desc, unsigned int size)
{
	struct list *list;
	struct router_info *router_info_tmp;

	slist_for_each (list, router_image->router_list) {
		router_info_tmp = (struct router_info *)list->data;

		if (router_desc &&
		    strcasecmp(router_info_tmp->router_name, router_desc) != 0)
			continue;

		if (!router_desc && router_info_tmp->file_size)
			continue;

		router_info_tmp->file_size = size;
	}
}

static int uboot_verify(struct router_image *router_image, const char *buff,
			unsigned int buff_len, int size)
{
	int ret;

	if (buff_len < 4)
		return 0;

	/* uboot magic header */
	if ((buff[0] != 0x27) || (buff[1] != 0x05) ||
	    (buff[2] != 0x19) || (buff[3] != 0x56))
		return 0;

	ret = router_image_add_file(router_image, "mr500.bin", size, size, 0);
	if (ret)
		return 0;

	ret = router_image_add_file(router_image, "firmware.bin", size, size, 0);
	if (ret)
		return 0;

	router_image->file_size = size;
	return 1;
}

static int ubnt_verify(struct router_image *router_image, const char *buff,
		       unsigned int buff_len, int size)
{
	if (buff_len < 4)
		return 0;

	/* ubnt magic header */
	if ((strncmp(buff, "UBNT", 4) != 0) &&
	    (strncmp(buff, "OPEN", 4) != 0))
		return 0;

	router_image->file_size = size;
	return 1;
}

static int ci_verify(struct router_image *router_image, const char *buff,
		     unsigned int buff_len, int size)
{
	unsigned int kernel_size, rootfs_size;
	int ret;

	if (buff_len < 64)
		return 0;

	/* combined image magic header */
	if ((buff[0] != 'C') || (buff[1] != 'I'))
		return 0;

	sscanf(buff, "CI%08x%08x", &kernel_size, &rootfs_size);
	if ((!kernel_size) || (!rootfs_size))
		return 0;

	ret = router_image_add_file(router_image, "kernel", kernel_size,
				    ((kernel_size + FLASH_PAGE_SIZE - 1) / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE,
				    64 * 1024);
	if (ret)
		return 0;

	ret = router_image_add_file(router_image, "rootfs", rootfs_size,
				    ((rootfs_size + FLASH_PAGE_SIZE - 1) / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE,
				    (64 * 1024) + kernel_size);
	if (ret)
		return 0;

	router_image->file_size = size - (64 * 1024);
	return 1;
}

static int strendswith(const char *str, const char *end)
{
	size_t end_len = strlen(end);
	size_t str_len = strlen(str);

	if (end_len > str_len)
		return 0;

	if (strcmp(&str[str_len - end_len], end) == 0)
		return 1;

	return 0;
}

static void ce_calculate_router_file_size(struct router_image *router_image)
{
	struct list *file_list = router_image->file_list;
	struct list *list;
	struct file_info *file_info_tmp;
	const char *router_desc;
	const char *file_name;
	unsigned int size;

	slist_for_each (list, file_list) {
		file_info_tmp = (struct file_info *)list->data;

		file_name = file_info_tmp->file_name;
		if (strncmp(file_name, fwupgradecfg, strlen(fwupgradecfg)) != 0)
			continue;

		if (strendswith(file_name, ".sig"))
			continue;

		router_desc = NULL;
		if (file_name[strlen(fwupgradecfg)] == '-')
			router_desc = &file_name[strlen(fwupgradecfg) + 1];

		size = fwupgrade_cfg_read_sizes(router_image, file_info_tmp);
		if (!size)
			continue;

		router_image_set_size(router_image, router_desc, size);
	}

}

static int ce_verify(struct router_image *router_image, const char *buff,
		     unsigned int buff_len, int size)
{
	char name_buff[33], *name_ptr, md5_buff[33];
	unsigned int num_files, hdr_offset, file_offset, file_size = 0;
	unsigned image_size = 0;
	unsigned int ce_version = 0, hdr_offset_sec;
	int ret;

	file_offset = 64 * 1024;

	if (buff_len < 100)
		return 0;

	/* ext combined image magic header */
	if ((buff[0] != 'C') || (buff[1] != 'E'))
		return 0;

	/* the old format does not have a version field */
	if (isxdigit(buff[2]) && isxdigit(buff[3])) {
		ret = sscanf(buff, "CE%02x", &ce_version);
		if (ret != 1)
			return 0;
	}

	switch (ce_version) {
	case 0:
		ret = sscanf(buff, "CE%10s%02x", name_buff, &num_files);
		if (ret != 2)
			return 0;

		hdr_offset = 14;
		hdr_offset_sec = 28;
		break;
	case 1:
		ret = sscanf(buff, "CE%*02x%32s%02x", name_buff, &num_files);
		if (ret != 2)
			return 0;

		hdr_offset = 38;
		hdr_offset_sec = 72;
		break;
	default:
		/* unsupported version */
		return 0;
	}

	name_ptr = strtok(name_buff, ",");
	while (name_ptr) {
		router_image_router_add(router_image, name_ptr);
		name_ptr = strtok(NULL, ",");
	}

	while (num_files > 0) {
		if (hdr_offset + hdr_offset_sec > buff_len) {
			fprintf(stderr, "Error - buffer too small to parse CE header\n");
			return 0;
		}

		switch (ce_version) {
		case 0:
			ret = sscanf(buff + hdr_offset, "%20s%08x", name_buff,
				     &file_size);
			if (ret != 2)
				return 0;

			break;
		case 1:
			ret = sscanf(buff + hdr_offset, "%32s%08x%32s",
				     name_buff, &file_size, md5_buff);
			if (ret != 3)
				return 0;

			break;
		}

		ret = router_image_add_file(router_image, name_buff, file_size,
					    file_size, file_offset);
		if (ret)
			return 0;

		file_offset += file_size;
		hdr_offset += hdr_offset_sec;
		num_files--;

		if (strncmp(name_buff, fwupgradecfg, strlen(fwupgradecfg)) == 0) {
			if (strlen(fwupgradecfg) + 1 < strlen(name_buff) &&
			    !strendswith(name_buff, ".sig"))
				router_image_router_add(router_image,
							&name_buff[strlen(fwupgradecfg)  + 1]);
			/***
			 * Don't add fwupgrade.cfg* files to the file size in
			 * order to detect the end-of-flash correctly.
			 */
			continue;
		}

		image_size += file_size;
	}

	if (image_size > (unsigned)size) {
		fprintf(stderr, "Error - bogus CE image: claimed size bigger than actual size\n");
		return 0;
	}

	router_image->file_size = image_size;

	/* calculate size of files referenced by fwupgrade.cfg of each router */
	ce_calculate_router_file_size(router_image);

	return 1;
}

static int zyxel_verify(struct router_image *router_image, const char *buff,
                       unsigned int buff_len, int size)
{
	/* zyxel header:
	 *   4 bytes:  checksum of the rootfs image
	 *   4 bytes:  length of the contained rootfs image file (big endian)
	 *  32 bytes:  Firmware Version string (NUL terminated, 0xff padded)
	 *   4 bytes:  checksum over the header partition (big endian - see below)
	 *  64 bytes:  Model (e.g. "NBG6617", NUL termiated, 0xff padded)
	 *   4 bytes:  checksum of the kernel partition
	 *   4 bytes:  length of the contained kernel image file (big endian)
	 *      rest:  0xff padding (To erase block size)
	 */
	struct zyxel_header {
		uint32_t rootfs_chksum;
		uint32_t rootfs_size;
		char firmware_version[32];
		uint32_t header_chksum;
		char model[64];
		uint32_t kernel_chksum;
		uint32_t kernel_size;
	};

	struct zyxel_header *zyxel_header;
	unsigned kernel_size, rootfs_size;
	unsigned zyxel_hdr_size = 64 * 1024;
	int ret;

	if (buff_len < sizeof(*zyxel_header))
		return 0;

	zyxel_header = (struct zyxel_header *)buff;
	kernel_size = ntohl(zyxel_header->kernel_size);
	rootfs_size = ntohl(zyxel_header->rootfs_size);

	if ((unsigned)size != zyxel_hdr_size + kernel_size + rootfs_size)
		return 0;

	ret = router_image_add_file(router_image, "ras.bin", size, size, 0);
	if (ret)
		return 0;

	router_image->file_size = size;
	return 1;
}

static int router_image_init_embedded(struct router_image *router_image)
{
	int ret = 0;

#if defined(LINUX) || defined(OSX)

	router_image->embedded_img = router_image->embedded_img_pre_check;
	ret = router_image->image_verify(router_image,
					 router_image->embedded_img_pre_check,
					 (unsigned)router_image->embedded_file_size,
					 (unsigned)router_image->embedded_file_size);
	if (ret != 1)
		router_image->embedded_img = NULL;
#elif defined(WIN32)
	HGLOBAL hGlobal;
	HRSRC hRsrc;
	int size;
	char *buff;

	hRsrc = FindResource(NULL, MAKEINTRESOURCE(router_image->embedded_img_res),
			     RT_RCDATA);
	if (hRsrc) {
		hGlobal = LoadResource(NULL, hRsrc);
		buff = LockResource(hGlobal);
		size = SizeofResource(NULL, hRsrc);

		router_image->embedded_img = buff;
		ret = router_image->image_verify(router_image, buff, size, size);
		if (ret != 1)
			router_image->embedded_img = NULL;
	}
#endif
	return ret;
}

struct router_image img_uboot = {
	.type = IMAGE_TYPE_UBOOT,
	.desc = "uboot image",
	.image_verify = uboot_verify,
};

struct router_image img_ubnt = {
	.type = IMAGE_TYPE_UBNT,
	.desc = "ubiquiti image",
	.image_verify = ubnt_verify,
};

struct router_image img_ci = {
	.type = IMAGE_TYPE_CI,
	.desc = "combined image",
	.image_verify = ci_verify,
};

struct router_image img_ce = {
	.type = IMAGE_TYPE_CE,
	.desc = "combined ext image",
	.image_verify = ce_verify,
};

struct router_image img_zyxel = {
	.type = IMAGE_TYPE_ZYXEL,
	.desc = "Zyxel image",
	.image_verify = zyxel_verify,
};

static struct router_image *router_images[] = {
	&img_uboot,
	&img_ubnt,
	&img_ci,
	&img_ce,
	&img_zyxel,
	NULL,
};

void router_images_init(void)
{
	struct router_image **router_image;

	for (router_image = router_images; *router_image; ++router_image)
		(*router_image)->file_list = NULL;
}

void router_images_init_embedded(void)
{
	struct router_image **router_image;
	int ret;

	for (router_image = router_images; *router_image; ++router_image) {
		if ((*router_image)->path || (*router_image)->embedded_img)
			continue;

		if (!(*router_image)->image_verify)
			continue;

		switch ((*router_image)->type) {
		case IMAGE_TYPE_UNKNOWN:
			continue;
		case IMAGE_TYPE_UBOOT:
#if defined(EMBED_UBOOT)
#if defined(LINUX)
			(*router_image)->embedded_img_pre_check = (char *)&_binary_img_uboot_start;
			(*router_image)->embedded_file_size = (unsigned long)&_binary_img_uboot_size;
#elif defined(OSX)
			(*router_image)->embedded_img_pre_check = getsectdata("__DATA", "_binary_img_uboot", &(*router_image)->embedded_file_size);
			if ((*router_image)->embedded_img_pre_check)
				(*router_image)->embedded_img_pre_check += _dyld_get_image_vmaddr_slide(0);
#elif defined(WIN32)
			(*router_image)->embedded_img_res = IDR_UBOOT_IMG;
#endif
#endif
			break;
		case IMAGE_TYPE_UBNT:
#if defined(EMBED_UBNT)
#if defined(LINUX)
			(*router_image)->embedded_img_pre_check = (char *)&_binary_img_ubnt_start;
			(*router_image)->embedded_file_size = (unsigned long)&_binary_img_ubnt_size;
#elif defined(OSX)
			(*router_image)->embedded_img_pre_check = getsectdata("__DATA", "_binary_img_ubnt", &(*router_image)->embedded_file_size);
			if ((*router_image)->embedded_img_pre_check)
				(*router_image)->embedded_img_pre_check += _dyld_get_image_vmaddr_slide(0);
#elif defined(WIN32)
			(*router_image)->embedded_img_res = IDR_UBNT_IMG;
#endif
#endif
			break;
		case IMAGE_TYPE_CI:
#if defined(EMBED_CI)
#if defined(LINUX)
			(*router_image)->embedded_img_pre_check = (char *)&_binary_img_ci_start;
			(*router_image)->embedded_file_size = (unsigned long)&_binary_img_ci_size;
#elif defined(OSX)
			(*router_image)->embedded_img_pre_check = getsectdata("__DATA", "_binary_img_ci", &(*router_image)->embedded_file_size);
			if ((*router_image)->embedded_img_pre_check)
				(*router_image)->embedded_img_pre_check += _dyld_get_image_vmaddr_slide(0);
#elif defined(WIN32)
			(*router_image)->embedded_img_res = IDR_CI_IMG;
#endif
#endif
			break;
		case IMAGE_TYPE_CE:
#if defined(EMBED_CE)
#if defined(LINUX)
			(*router_image)->embedded_img_pre_check = (char *)&_binary_img_ce_start;
			(*router_image)->embedded_file_size = (unsigned long)&_binary_img_ce_size;
#elif defined(OSX)
			(*router_image)->embedded_img_pre_check = getsectdata("__DATA", "_binary_img_ce", &(*router_image)->embedded_file_size);
			if ((*router_image)->embedded_img_pre_check)
				(*router_image)->embedded_img_pre_check += _dyld_get_image_vmaddr_slide(0);
#elif defined(WIN32)
			(*router_image)->embedded_img_res = IDR_CE_IMG;
#endif
#endif
			break;
		case IMAGE_TYPE_ZYXEL:
#if defined(EMBED_ZYXEL)
#if defined(LINUX)
			(*router_image)->embedded_img_pre_check = (char *)&_binary_img_zyxel_start;
			(*router_image)->embedded_file_size = (unsigned long)&_binary_img_zyxel_size;
#elif defined(OSX)
			(*router_image)->embedded_img_pre_check = getsectdata("__DATA", "_binary_img_zyxel", &(*router_image)->embedded_file_size);
			if ((*router_image)->embedded_img_pre_check)
				(*router_image)->embedded_img_pre_check += _dyld_get_image_vmaddr_slide(0);
#elif defined(WIN32)
			(*router_image)->embedded_img_res = IDR_ZYXEL_IMG;
#endif
#endif
			break;
		}

		ret = router_image_init_embedded(*router_image);
		if (ret != 1)
			continue;

#if defined(DEBUG)
		printf("init embedded image: %s found (%u bytes)\n",
		       (*router_image)->desc, (*router_image)->file_size);
#endif
	}
}

void router_images_print_desc(void)
{
	struct router_image **router_image;

	for (router_image = router_images; *router_image; ++router_image)
		fprintf(stderr, " * %s\n", (*router_image)->desc);
}

int router_images_verify_path(const char *image_path)
{
	struct router_image **router_image;
	char *file_buff = NULL, found_consumer = 0;
	unsigned int file_buff_size = 64 * 1024; // max CE hdr size
	int fd, file_size, ret = -1, len;

	file_buff = malloc(file_buff_size);
	if (!file_buff)
		goto out;

	fd = open(image_path, O_RDONLY | O_BINARY);
	if (fd < 0) {
		fprintf(stderr, "Error - can't open image file '%s': %s\n",
			image_path, strerror(errno));
		goto out;
	}

	ret = (int)read(fd, file_buff, file_buff_size);
	if (ret < 0) {
		fprintf(stderr, "Error - can't read image file '%s': %s\n",
			image_path, strerror(errno));
		goto close_fd;
	}

	len = ret;
	for (router_image = router_images; *router_image; ++router_image) {
		if ((*router_image)->path || (*router_image)->embedded_img)
			continue;

		if (!(*router_image)->image_verify)
			continue;

		file_size = (int)lseek(fd, 0, SEEK_END);
		if (file_size < 0) {
			fprintf(stderr, "Unable to retrieve file size of '%s': %s\n",
				image_path, strerror(errno));
			continue;
		}

		(*router_image)->path = image_path;
		ret = (*router_image)->image_verify((*router_image), file_buff,
						    len, file_size);
		if (ret != 1) {
			(*router_image)->path = NULL;
			continue;
		}

		found_consumer = 1;

#if defined(DEBUG)
		printf("verify image path: %s: %s (%i bytes)\n",
		       image_path, (*router_image)->desc,
		       (*router_image)->file_size);
#endif
	}

	if (!found_consumer)
		fprintf(stderr, "Unsupported image '%s': ignoring file\n",
			image_path);

	ret = 0;

close_fd:
	close(fd);
out:
	free(file_buff);
	return ret;
}

int router_images_open_path(struct node *node)
{
	/* embedded image */
	if ((!node->router_type->image->path) &&
	    (node->router_type->image->embedded_img) &&
	    (node->router_type->image->file_size > 0)) {
		    node->image_state.fd = 1;
		    goto out;
	}

	node->image_state.fd = open(node->router_type->image->path,
				    O_RDONLY | O_BINARY);
	if (node->image_state.fd < 0)
		fprintf(stderr, "Error - can't open image file '%s': %s\n",
			node->router_type->image->path, strerror(errno));

out:
	return node->image_state.fd;
}

int router_images_read_data(char *dst, struct node *node)
{
	int len = TFTP_PAYLOAD_SIZE, read_len;
	uint8_t *file_data;
	off_t reto;

	if (node->image_state.flash_size - node->image_state.bytes_sent < TFTP_PAYLOAD_SIZE)
		len = node->image_state.flash_size - node->image_state.bytes_sent;

	read_len = len;

	if (node->image_state.file_size < node->image_state.bytes_sent)
		read_len = 0;
	else if (node->image_state.file_size < node->image_state.bytes_sent + len)
		read_len = node->image_state.file_size - node->image_state.bytes_sent;

	if (node->router_type->image->path) {
		if (node->image_state.fd < 0) {
#if defined(DEBUG)
			fprintf(stderr, "router_images_read_data(): image has file path but no open fd ??\n");
#endif
			goto err;
		}

		if (read_len > 0) {
			reto = lseek(node->image_state.fd,
				     node->image_state.bytes_sent + node->image_state.offset,
				     SEEK_SET);
			if (reto == (off_t) -1) {
				fprintf(stderr, "Error - seeking in file '%s': %s\n",
					node->router_type->image->path,
					strerror(errno));
				return -1;
			}

			if (read_len != read(node->image_state.fd, dst, read_len)) {
				fprintf(stderr, "Error - reading from file '%s': %s\n",
					node->router_type->image->path,
					strerror(errno));
				return -1;
			}
		}

		if (read_len != len)
			memset(dst + read_len, 0, len - read_len);

		return len;
	} else if (node->router_type->image->embedded_img) {
		file_data = (uint8_t *)node->router_type->image->embedded_img;
		file_data += node->image_state.bytes_sent;
		file_data += node->image_state.offset;

		if (read_len > 0)
			memcpy(dst, file_data, read_len);

		if (read_len != len)
			memset(dst + read_len, 0, len - read_len);

		return len;
	}

err:
	return -1;
}

bool router_images_available(void)
{
	struct router_image **router_image;

	for (router_image = router_images; *router_image; ++router_image) {
		if ((*router_image)->path || (*router_image)->embedded_img)
			return true;
	}

	return false;
}

void router_images_close_path(struct node *node)
{
	if ((node->router_type->image->path) &&
	    (node->image_state.fd > 0))
		close(node->image_state.fd);

	node->image_state.fd = -1;
}
