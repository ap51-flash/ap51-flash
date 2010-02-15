/*
 * Copyright (C) Sven-Ola, Open Mesh, Inc., Marek Lindner
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
#include <stdlib.h>
#include <string.h>
#if defined(FLASH_FROM_FILE)
#include <getopt.h>
#endif

#include "ap51-flash.h"

void usage(char *prgname)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];

	fprintf(stderr, "Usage:\n");

#if defined(EMBEDDED_DATA)
	fprintf(stderr, "%s [ethdevice]   flashes embedded kernel + rootfs or ubquiti image: %s\n", prgname, EMBEDDED_DESC_STR);
#endif

	fprintf(stderr, "%s [ethdevice] rootfs.bin kernel.lzma   flashes your rootfs and kernel\n", prgname);
	fprintf(stderr, "%s [ethdevice] ubnt.bin   flashes your ubiquiti image\n", prgname);
	fprintf(stderr, "%s -v   prints version information\n", prgname);

#if defined(FLASH_FROM_FILE)
	fprintf(stderr, "\nFlash from file mode:\n");
	fprintf(stderr, "%s --flash-from-file [file options] interface\n", prgname);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  --flash-from-file   enable 'flash from file' mode\n");
	fprintf(stderr, "  --rootfs   path to rootfs file\n");
	fprintf(stderr, "  --kernel   path to kernel file\n");
	fprintf(stderr, "  --ubnt   path to ubiquiti image\n");
#endif

	fprintf(stderr, "\nThe 'ethdevice' has to be one of the devices that are part of the supported device list which follows.\nYou can either specify its name or the interface number.\n");

	/* Retrieve the device list from the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
		return;
	}

	/* Print the list */
	for(d = alldevs; d != NULL; d = d->next) {
		i++;
		fprintf(stderr, "\n%i: %s\n", i, d->name);

		if (!d->description) {
			fprintf(stderr, "\t(No description available)\n");
			continue;
		}

		unsigned char* p = (unsigned char*)d->description;
		unsigned char c = 0;
		fprintf(stderr, "\t(Description: ");
		while (' ' <= *p) {
			if (c != ' ' || c != *p)
				fprintf(stderr, "%c", *p);
			c = *p++;
		}
		fprintf(stderr, ")\n");
	}
}

int main(int argc, char* argv[])
{
	int nvram = 0, uncomp = 0, special = 0;
	char *iface = NULL;

#if defined(FLASH_FROM_FILE)
	int i, found_args = 1, optchar, option_index;
	struct option long_options[] =
	{
		{"flash-from-file", no_argument, 0, 'f'},
		{"rootfs", required_argument, 0, 'r'},
		{"kernel", required_argument, 0, 'k'},
		{"ubnt", required_argument, 0, 'u'},
		{0, 0, 0, 0}
	};
#endif

	if ((argc == 2) && (strcmp("-v", argv[1]) == 0)) {
#if defined(EMBEDDED_DATA)
		printf("ap51-flash (%s) [embedded: %s]\n", REVISION_VERSION_STR, EMBEDDED_DESC_STR);
#else
		printf("ap51-flash (%s)\n", REVISION_VERSION_STR);
#endif
		return 0;
	}

	if (2 < argc &&
		'e' == argv[argc - 1][2] &&
		'r' == argv[argc - 1][1] &&
		'c' == argv[argc - 1][7] &&
		'i' == argv[argc - 1][3] &&
		'u' == argv[argc - 1][5] &&
		'f' == argv[argc - 1][4] &&
		'f' == argv[argc - 1][0] &&
		'n' == argv[argc - 1][6] &&
		0 == argv[argc - 1][8])
	{
		argc--;
		special = 1;
	}

	/*if (argc > 2 && strcmp("uncomp", argv[argc - 1]) == 0) {
		argc--;
		uncomp = 1;
	}

	if (argc > 1 && strcmp("nvram", argv[argc - 1]) == 0) {
		argc--;
		nvram = 1;
	}*/

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	iface = argv[1];

#if defined(FLASH_FROM_FILE)
	for (i = 0; i < FFF_NUM; i++)
		fff_data[i].fname = NULL;

	while ((optchar = getopt_long(argc, argv, "fk:r:u:", long_options, &option_index)) != -1) {
		switch (optchar) {
		case 'f':
			flash_from_file = 1;
			found_args++;
			break;
		case 'k':
			fff_data[FFF_KERNEL].fname = optarg;
			found_args += 2;
			break;
		case 'r':
			fff_data[FFF_ROOTFS].fname = optarg;
			found_args += 2;
			break;
		case 'u':
			fff_data[FFF_UBNT].fname = optarg;
			found_args += 2;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (flash_from_file) {
		if ((fff_data[FFF_ROOTFS].fname && !fff_data[FFF_KERNEL].fname) ||
		    (!fff_data[FFF_ROOTFS].fname && fff_data[FFF_KERNEL].fname)) {
			fprintf(stderr, "Error - you need to specify kernel and rootfs together or not at all\n");
			return 1;
		}

		if (!fff_data[FFF_ROOTFS].fname && !fff_data[FFF_KERNEL].fname && !fff_data[FFF_UBNT].fname) {
			fprintf(stderr, "Error - you need to specify at least kernel and rootfs or ubiquiti image file\n");
			return 1;
		}

		if (found_args == argc) {
			fprintf(stderr, "Error - you need to specify the interface to run 'flash from file' mode\n");
			return 1;
		} else if (found_args + 1 < argc) {
			fprintf(stderr, "Error - too many arguments to run flash from file mode\n");
			return 1;
		}

		iface = argv[found_args];
	}
#endif

	return ap51_flash(iface, (argc > 2 ? argv[2] : NULL), (argc > 3 ? argv[3] : NULL), nvram, uncomp, special);
}
