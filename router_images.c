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
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>

#include "types.h"
#include "router_images.h"
#include "flash.h"
#include "ap51-flash-res.h"

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

struct file_info *router_image_get_file(struct list *file_list, char *file_name)
{
	struct list *list;
	struct file_info *file_info = NULL, *file_info_tmp;

	for (list = file_list; list; list = list->next) {
		file_info_tmp = (struct file_info *)list->data;

		if (strcmp(file_info_tmp->file_name, file_name) != 0)
			continue;

		file_info = file_info_tmp;
		break;
	}

	return file_info;
}

static struct file_info *_router_image_add_file(struct router_image *router_image,
						char *file_name)
{
	struct list *list;
	struct file_info *file_info;

	file_info = router_image_get_file(router_image->file_list, file_name);
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
	strcpy(file_info->file_name, file_name);
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

static int router_image_add_file(struct router_image *router_image, char *file_name,
				 int file_size, int file_fsize, int file_offset)
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

static int uboot_verify(struct router_image *router_image, char *buff,
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

	router_image->file_size = size;
	return 1;
}

static int uboot_init(void)
{
	int ret = 0;
#if defined(EMBED_UBOOT)
#if defined(LINUX)
	ret = uboot_verify(&img_uboot, (char *)&_binary_img_uboot_start,
			   (unsigned long)&_binary_img_uboot_size,
			   (unsigned long)&_binary_img_uboot_size);
	if (ret == 1)
		img_uboot.embedded_img = (char *)&_binary_img_uboot_start;
#elif defined(WIN32)
	HGLOBAL hGlobal;
	HRSRC hRsrc;
	int size;
	char *buff;

	hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_UBOOT_IMG), RT_RCDATA);
	if (hRsrc) {
		hGlobal = LoadResource(NULL, hRsrc);
		buff = LockResource(hGlobal);
		size = SizeofResource(NULL, hRsrc);

		ret = uboot_verify(&img_uboot, buff, size, size);
		if (ret == 1)
			img_uboot.embedded_img = buff;
	}
#endif
#endif /* EMBED_UBOOT */
	return ret;
}

static int ubnt_verify(struct router_image *router_image, char *buff,
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

static int ubnt_init(void)
{
	int ret = 0;
#if defined(EMBED_UBNT)
#if defined(LINUX)
	ret = ubnt_verify(&img_ubnt, (char *)&_binary_img_ubnt_start,
			  (unsigned long)&_binary_img_ubnt_size,
			  (unsigned long)&_binary_img_ubnt_size);
	if (ret == 1)
		img_ubnt.embedded_img = (char *)&_binary_img_ubnt_start;
#elif defined(WIN32)
	HGLOBAL hGlobal;
	HRSRC hRsrc;
	int size;
	char *buff;

	hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_UBNT_IMG), RT_RCDATA);
	if (hRsrc) {
		hGlobal = LoadResource(NULL, hRsrc);
		buff = LockResource(hGlobal);
		size = SizeofResource(NULL, hRsrc);

		ret = ubnt_verify(&img_ubnt, buff, size, size);
		if (ret == 1)
			img_ubnt.embedded_img = buff;
	}
#endif
#endif /* EMBED_UBNT */
	return ret;
}

static int ci_verify(struct router_image *router_image, char *buff,
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

static int ci_init(void)
{
	int ret = 0;
#if defined(EMBED_CI)
#if defined(LINUX)
	ret = ci_verify(&img_ci, (char *)&_binary_img_ci_start,
			(unsigned long)&_binary_img_ci_size,
			(unsigned long)&_binary_img_ci_size);
	if (ret == 1)
		img_ci.embedded_img = (char *)&_binary_img_ci_start;
#elif defined(WIN32)
	HGLOBAL hGlobal;
	HRSRC hRsrc;
	int size;
	char *buff;

	hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_CI_IMG), RT_RCDATA);
	if (hRsrc) {
		hGlobal = LoadResource(NULL, hRsrc);
		buff = LockResource(hGlobal);
		size = SizeofResource(NULL, hRsrc);

		ret = ci_verify(&img_ci, buff, size, size);
		if (ret == 1)
			img_ci.embedded_img = buff;
	}
#endif
#endif /* EMBED_CI */
	return ret;
}

static int ce_verify_om2p(struct router_image *router_image, char *buff,
			  unsigned int buff_len, int size)
{
	char name_buff[33], md5_buff[33];
	unsigned int num_files, hdr_offset, file_offset, file_size;
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

	if (strstr(name_buff, "OM2P") == NULL)
		return 0;

	while (num_files > 0) {
		if (hdr_offset + hdr_offset_sec > buff_len) {
			fprintf(stderr, "Error - buffer too small to parse CE header\n");
			return 0;
		}

		switch (ce_version) {
		case 0:
			ret = sscanf(buff + hdr_offset, "%20s%08x", name_buff, &file_size);
			if (ret != 2)
				return 0;

			break;
		case 1:
			ret = sscanf(buff + hdr_offset, "%32s%08x%32s", name_buff, &file_size, md5_buff);
			if (ret != 3)
				return 0;

			break;
		}

		ret = router_image_add_file(router_image, name_buff, file_size, file_size, file_offset);
		if (ret)
			return 0;

		file_offset += file_size;
		hdr_offset += hdr_offset_sec;
		num_files--;
	}

	router_image->file_size = size - (64 * 1024);
	return 1;
}

static int ce_init_om2p(void)
{
	int ret = 0;
#if defined(EMBED_CE)
#if defined(LINUX)
	ret = ce_verify_om2p(&img_ce_om2p, (char *)&_binary_img_ce_start,
			     (unsigned long)&_binary_img_ce_size,
			     (unsigned long)&_binary_img_ce_size);
	if (ret == 1)
		img_ce_om2p.embedded_img = (char *)&_binary_img_ce_start;
#elif defined(WIN32)
	HGLOBAL hGlobal;
	HRSRC hRsrc;
	int size;
	char *buff;

	hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_CE_IMG), RT_RCDATA);
	if (hRsrc) {
		hGlobal = LoadResource(NULL, hRsrc);
		buff = LockResource(hGlobal);
		size = SizeofResource(NULL, hRsrc);

		ret = ce_verify_om2p(&img_ce_om2p, buff, size, size);
		if (ret == 1)
			img_ce_om2p.embedded_img = buff;
	}
#endif
#endif /* EMBED_CE */
	return ret;
}

struct router_image img_uboot = {
	.desc = "uboot image",
	.image_init = uboot_init,
	.image_verify = uboot_verify,
};

struct router_image img_ubnt = {
	.desc = "ubiquiti image",
	.image_init = ubnt_init,
	.image_verify = ubnt_verify,
};

struct router_image img_ci = {
	.desc = "combined image",
	.image_init = ci_init,
	.image_verify = ci_verify,
};

struct router_image img_ce_om2p = {
	.desc = "combined ext image (OM2P)",
	.image_init = ce_init_om2p,
	.image_verify = ce_verify_om2p,
};

static struct router_image *router_images[] = {
	&img_uboot,
	&img_ubnt,
	&img_ci,
	&img_ce_om2p,
	NULL,
};

void router_images_init(void)
{
	struct router_image **router_image;
	int ret;

	for (router_image = router_images; *router_image; ++router_image) {
		(*router_image)->file_list = NULL;

		if (!(*router_image)->image_init)
			continue;

		ret = (*router_image)->image_init();
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

int router_images_verify_path(char *image_path)
{
	struct router_image **router_image;
	char *file_buff = NULL, found_consumer = 0;
	unsigned int file_buff_size = 300;
	int fd, file_size, ret = -1, len;

	file_buff = malloc(file_buff_size);
	if (!file_buff_size)
		goto out;

	fd = open(image_path, O_RDONLY | O_BINARY);
	if (fd < 0) {
		fprintf(stderr, "Error - can't open image file '%s': %s\n", image_path, strerror(errno));
		goto out;
	}

	ret = read(fd, file_buff, file_buff_size);
	if (ret < 0) {
		fprintf(stderr, "Error - can't read image file '%s': %s\n", image_path, strerror(errno));
		goto close_fd;
	}

	len = ret;
	for (router_image = router_images; *router_image; ++router_image) {
		if (!(*router_image)->image_verify)
			continue;

		file_size = lseek(fd, 0, SEEK_END);
		if (file_size < 0) {
			fprintf(stderr, "Unable to retrieve file size of '%s': %s\n", image_path, strerror(errno));
			continue;
		}

		ret = (*router_image)->image_verify((*router_image), file_buff, len, file_size);
		if (ret != 1)
			continue;

		(*router_image)->path = image_path;
		found_consumer = 1;

#if defined(DEBUG)
		printf("verify image path: %s: %s (%i bytes)\n",
		       image_path, (*router_image)->desc, (*router_image)->file_size);
#endif
	}

	if (!found_consumer)
		fprintf(stderr, "Unsupported image '%s': ignoring file\n", image_path);

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

	node->image_state.fd = open(node->router_type->image->path, O_RDONLY | O_BINARY);
	if (node->image_state.fd < 0)
		fprintf(stderr, "Error - can't open image file '%s': %s\n",
			node->router_type->image->path, strerror(errno));

out:
	return node->image_state.fd;
}

int router_images_read_data(char *dst, struct node *node)
{
	int len = TFTP_PAYLOAD_SIZE, read_len;

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
			lseek(node->image_state.fd, node->image_state.bytes_sent + node->image_state.offset, SEEK_SET);

			if (read_len != read(node->image_state.fd, dst, read_len)) {
				fprintf(stderr, "Error - reading from file '%s': %s\n",
					node->router_type->image->path, strerror(errno));
				return -1;
			}
		}

		if (read_len != len)
			memset(dst + read_len, 0, len - read_len);

		return len;
	} else if (node->router_type->image->embedded_img) {
		if (read_len > 0)
			memcpy(dst,
			       (void *)(node->router_type->image->embedded_img + node->image_state.bytes_sent + node->image_state.offset),
			       read_len);

		if (read_len != len)
			memset(dst + read_len, 0, len - read_len);

		return len;
	}

err:
	return -1;
}

void router_images_close_path(struct node *node)
{
	if ((node->router_type->image->path) &&
	    (node->image_state.fd > 0))
		close(node->image_state.fd);

	node->image_state.fd = -1;
}
