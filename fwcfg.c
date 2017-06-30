/***
 *
 * Copyright (C) 2012-2015 Open Mesh, Inc.
 *
 * The reproduction and distribution of this software without the written
 * consent of Open-Mesh, Inc. is prohibited by the United States Copyright
 * Act and international treaties.
 *
 ***/

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stddef.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "fwcfg.h"
#include "types.h"
#include "router_images.h"
#include "flash.h"

static void rtrim(char *s)
{
	size_t len = strlen(s);
	char *t = &s[len];

	while (t-- && t >= s) {
		if (!isspace(*t))
			break;

		*t = '\0';
	}
}

static unsigned int fwcfg_parse_sizes(struct router_image *router_image,
				      char *content)
{
	char *line, *str_start, *saveptr;
	size_t line_len;
	char *value, *type, *tv_delim;
	unsigned int size = 0;
	const char *section = NULL;
	struct file_info *file_info;

	/* parse */
	for (str_start = content; ; str_start = NULL) {
		line = strtok_r(str_start, "\n", &saveptr);
		if (!line)
			break;

		if (strlen(line) == 0)
			continue;

		if (!section && line[0] != '[') {
			fprintf(stderr, "Found line before section: %s\n",
				line);
			return 0;
		}

		if (line[0] == '[') {
			/* section */
			rtrim(line);
			line_len = strlen(line);
			if (line[line_len - 1] != ']') {
				fprintf(stderr,
					"Found section line without delimiter: %s\n",
					line);
				return 0;
			}

			line[line_len - 1] = '\0';

			section = &line[1];
		} else {
			/* type value pair */
			type = line;
			tv_delim = strchr(line, '=');
			if (!tv_delim) {
				fprintf(stderr,
					"Found type=value line without '=': %s\n",
					line);
				return 0;
			}

			tv_delim[0] = '\0';
			value = &tv_delim[1];

			if (strcmp("filename", type) != 0)
				continue;

			file_info = router_image_get_file_info(router_image,
							       value);
			if (!file_info) {
				fprintf(stderr,
					"Failed to find file %s referenced in fwupgrade.cfg\n",
					value);
				return 0;
			}

			size += file_info->file_size;
		}
	}

	return size;
}

unsigned int fwupgrade_cfg_read_sizes(struct router_image *router_image,
				      struct file_info *file_info)
{
	int fd = -1;
	int size = 0;
	int read_len;
	char *dst = NULL;

	/*
	 * WARNING only call when calle first verified that image size is
	 * correct and offset/size of files don't violate the size
	 */

	read_len = file_info->file_size;
	dst = malloc(read_len + 1);
	if (!dst) {
		fprintf(stderr, "Error - allocate memory for '%s': %s\n",
			file_info->file_name, strerror(errno));
		goto out;
	}

	if (router_image->path) {
		fd = open(router_image->path, O_RDONLY | O_BINARY);
		if (fd < 0) {
			fprintf(stderr, "Error - can't open image file '%s': %s\n",
				router_image->path, strerror(errno));
			goto out;
		}

		if (read_len > 0) {
			lseek(fd, file_info->file_offset, SEEK_SET);

			if (read_len != read(fd, dst, read_len)) {
				fprintf(stderr, "Error - reading from file '%s': %s\n",
					router_image->path, strerror(errno));
				goto out;
			}
		}
	} else if (router_image->embedded_img) {
		if (read_len > 0)
			memcpy(dst,
			       (void *)(router_image->embedded_img + file_info->file_offset),
			       read_len);
	}

	dst[read_len] = '\0';
	size = fwcfg_parse_sizes(router_image, dst);

out:
	if (fd >= 0)
		close(fd);
	free(dst);

	return size;
}
