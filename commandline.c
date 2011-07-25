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

#include <stdio.h>
#include <string.h>

#include "types.h"
#include "flash.h"
#include "socket.h"
#include "router_images.h"

#ifndef REVISION_VERSION
#define REVISION_VERSION_STR "version information not available"
#else
#define REVISION_VERSION_STR REVISION_VERSION
#endif

void usage(char *prgname)
{
	fprintf(stderr, "Usage:\n");

	fprintf(stderr, "%s interface image\tflash router with given image\n", prgname);
	fprintf(stderr, "%s -v\t\t\tprints version information\n", prgname);

	fprintf(stderr, "\nOne or multiple images of the following type can be specified:\n");
	router_images_print_desc();

	fprintf(stderr, "\nThe interface has to be one of the devices that are part of the supported device list which follows.\nYou can either specify its name or the interface number.\n");
	socket_print_all_ifaces();
}

int main(int argc, char* argv[])
{
	char *iface = NULL;
	int ret = -1;

	if ((argc == 2) && (strcmp("-v", argv[1]) == 0)) {
#if defined(EMBEDDED_DESC)
		printf("ap51-flash (%s) [embedded: %s]\n", REVISION_VERSION_STR, EMBEDDED_DESC);
#else
		printf("ap51-flash (%s)\n", REVISION_VERSION_STR);
#endif
		return 0;
	}

	if (argc < 2) {
		fprintf(stderr, "Error - no interface specified\n");
		usage(argv[0]);
		goto out;
	}

	if (strlen(argv[1]) < 3)
		iface = socket_find_iface_by_index(argv[1]);

	if (!iface)
		iface = argv[1];

	argc -= 2;
	argv += 2;

	router_images_init();

	while (argc > 0) {
		ret = router_images_verify_path(argv[0]);
		if (ret < 0)
			goto out;

		argc -= 1;
		argv += 1;
	}

#if defined(DEBUG)
	printf("Listening on interface: %s\n", iface);
#endif

	ret = flash(iface);

out:
	return ret;
}
