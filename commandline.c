// SPDX-License-Identifier: GPL-3.0-or-later
/* SPDX-FileCopyrightText: 2009-2019, Marek Lindner <mareklindner@neomailbox.ch>
 */

#include "commandline.h"

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "flash.h"
#include "router_images.h"
#include "router_types.h"
#include "socket.h"

#ifndef SOURCE_VERSION
#define SOURCE_VERSION "2019.0.1+"
#endif

static void usage(const char *prgname)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "%s interface image\t\t\tflash router with given image\n",
		prgname);
	fprintf(stderr, "%s [-m <MAC>...] interface image\tflash router at given MAC address(es)\n", prgname);
	fprintf(stderr, "%s -h\t\t\t\t\tshow usage/help\n", prgname);
	fprintf(stderr, "%s -v\t\t\t\t\tprints version information\n", prgname);

	fprintf(stderr, "\nOne or multiple images of the following type can be specified:\n");
	router_images_print_desc();

	fprintf(stderr, "\nThe interface has to be one of the devices that are part of the supported device list which follows.\nYou can either specify its name or the interface number.\n");
	socket_print_all_ifaces();
}

#if defined(WIN32) && defined(NPCAP)

#include <tchar.h>
#include <delayimp.h>

static FARPROC WINAPI npcap_load_delayed_failure_hook(unsigned dliNotify,
						      PDelayLoadInfo pdli)
{
    if (dliNotify == dliFailLoadLib)
        fprintf(stderr, "Unable to load Npcap library: %s\n", pdli->szDll);
    else if (dliNotify == dliFailGetProc)
        fprintf(stderr, "Unable to load find procedure %s in %s\n",
		pdli->dlp.szProcName, pdli->szDll);

    return FALSE;
}

static int npcap_load_delayed(void)
{
	_TCHAR npcap_dir[512];
	UINT len;

	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %lx", GetLastError());
		return -1;
	}

	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %lx", GetLastError());
		return -1;
	}

	 __pfnDliFailureHook2 = npcap_load_delayed_failure_hook;
	return 0;
}
#endif

int main(int argc, char* argv[])
{
	bool print_help = false;
	bool print_version = false;
	int c;
	char *iface = NULL;
	int ret = -1;
	bool load_embedded = true;
	const char *progname = "ap51-flash";
	static struct option long_options[] = {
		{"help",	no_argument,		0,	'h'},
		{"version",	no_argument,		0,	'v'},
		{"mac",		required_argument,	0,	'm'},
		{}
	};

#if defined(WIN32) && defined(NPCAP)
	npcap_load_delayed();
#endif

	while ((c = getopt_long(argc, argv, "hvm:", long_options, NULL)) != -1) {
		switch (c) {
		case 'h':
			print_help = true;
			ret = 0;
			break;
		case 'v':
			print_version = true;
			ret = 0;
			break;
		case 'm':
			if (mac_whitelist_add(optarg) == 0)
				break;
			/* fall-through */
		case '?':
			print_help = true;
			break;
		}
	}

	progname = argv[0];
	if (print_help) {
		usage(progname);
		goto out;
	}

	if (print_version) {
#if defined(EMBEDDED_DESC)
		printf("ap51-flash (%s) [embedded: %s]\n", SOURCE_VERSION,
		       EMBEDDED_DESC);
#else
		printf("ap51-flash (%s)\n", SOURCE_VERSION);
#endif
		goto out;
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		fprintf(stderr, "Error - no interface specified\n");
		usage(progname);
		goto out;
	}

	iface = socket_find_iface_by_index(argv[0]);
	if (!iface)
		iface = argv[0];

	argc -= 1;
	argv += 1;

	router_images_init();

	while (argc > 0) {
		ret = router_images_verify_path(argv[0]);
		if (ret < 0)
			goto out;

		argc -= 1;
		argv += 1;
		load_embedded = false;
	}

	if (load_embedded) {
		router_images_init_embedded();
	} else {
#if defined(EMBED_UBOOT) || defined(EMBED_UBNT) || defined(EMBED_CI) || defined(EMBED_CE) || defined(EMBED_ZYXEL)
		printf("Embedded image disabled\n");
#endif
	}

#if defined(DEBUG)
	printf("Listening on interface: %s\n", iface);
#endif

	if (!router_images_available()) {
		fprintf(stderr, "Error - no images specified\n");
		usage(progname);
		goto out;
	}

	ret = flash_start(iface);

out:
	return ret;
}
