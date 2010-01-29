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
	int nvram = 0;
	int uncomp = 0;
	int special = 0;

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
#ifdef _DEBUG
	special = 1;
#endif

/*	if (argc > 2 && 0 == strcmp("uncomp", argv[argc - 1]))
	{
		argc--;
		uncomp = 1;
	}

	if (argc > 1 && 0 == strcmp("nvram", argv[argc - 1]))
	{
		argc--;
		nvram = 1;
	}*/

	if (argc < 2)
	{
		usage(argv[0]);
		return 1;
	}

	return ap51_flash(argv[1], 2 < argc ? argv[2] : NULL, 3 < argc ? argv[3] : NULL, nvram, uncomp, special);
}
