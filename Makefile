#
# Copyright (C) Sven-Ola, Open Mesh, Inc., Marek Lindner
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 3 of the GNU General Public
# License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA
#

CC      = $(CROSS)gcc
AR      = $(CROSS)ar
STRIP   = $(CROSS)strip
OBJCOPY = $(CROSS)objcopy
WINDRES = $(CROSS)windres
CFLAGS  = -Wall -ggdb -I. -IWpdPack/Include/ -fno-strict-aliasing -fpack-struct -Os
LIB_OBJS= ap51-flash.o uip.o uip_arp.o timer.o clock-arch.o psock.o packet.o
OBJS    = $(LIB_OBJS) main.o
AP51_RC = ap51-flash-res

# if you change the names here you also need to change the ap51-flash.c code
EMBED_KERNEL = openwrt-atheros-vmlinux.lzma
EMBED_ROOTFS = openwrt-atheros-root.squashfs
EMBED_UBNT_IMG = openwrt-atheros-ubnt2-squashfs.bin

ifneq ($(wildcard $(EMBED_KERNEL)),)
ifneq ($(wildcard $(EMBED_ROOTFS)),)
ifneq ($(wildcard $(EMBED_UBNT_IMG)),)
CFLAGS += -DEMBEDDED_DATA
LIN_OBJS = kernel.o rootfs.o ubnt_img.o
WIN_OBJS = $(AP51_RC).o
$(shell echo '#include "ap51-flash-res.h"' > $(AP51_RC))
$(shell echo 'IDR_KERNEL RCDATA DISCARDABLE "$(EMBED_KERNEL)"' >> $(AP51_RC))
$(shell echo 'IDR_ROOTFS RCDATA DISCARDABLE "$(EMBED_ROOTFS)"' >> $(AP51_RC))
$(shell echo 'IDR_UBNT_IMG RCDATA DISCARDABLE "$(EMBED_UBNT_IMG)"' >> $(AP51_RC))
ifneq ($(DESC),)
CFLAGS += -DEMBEDDED_DESC=\"$(DESC)\"
endif
endif
endif
endif

REVISION = $(shell if [ -d .svn ]; then \
				if which svn > /dev/null; then \
					svn info | grep "Rev:" | sed -e '1p' -n | awk '{print "r"$$4}'; \
				fi \
			 else \
				if [ -d .git ]; then \
					git_rev=`git log --grep="git-svn-id" -n1 --format=short | grep commit | awk '{print $$2}'`; \
					git svn find-rev $$git_rev | awk '{print "r"$$1"g"}'; \
				fi; \
			 fi)

ifeq ($(REVISION),)
CFLAGS += -DREVISION_VERSION=\"unknown\"
else
CFLAGS += -DREVISION_VERSION=\"$(REVISION)\"
endif

#CFLAGS += -D_DEBUG

all: ap51-flash

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

libap51-flash.a: $(LIB_OBJS) Makefile
	$(AR) rcs $@ $(LIB_OBJS) $(LDFLAGS)

ap51-flash: $(LIN_OBJS) $(OBJS) Makefile
	$(CC) $(CFLAGS) $(LIN_OBJS) $(OBJS) $(LDFLAGS) -lpcap -o $@
	$(STRIP) $@

ap51-flash-static: $(LIN_OBJS) $(OBJS) libap51-flash.a Makefile
	$(CC) $(CFLAGS) $(LIN_OBJS) $(OBJS) $(LDFLAGS) -lpcap -static -o $@
	$(STRIP) $@

ap51-flash.exe: $(WIN_OBJS) $(OBJS) Makefile
	$(CC) $(CFLAGS) -LWpdPack/Lib/ -DWIN32 -D_CONSOLE -D_MBCS $(WIN_OBJS) $(OBJS) $(LDFLAGS) -lwpcap -static -o $@
	$(STRIP) $@

kernel.o: $(EMBED_KERNEL)
	$(OBJCOPY) -B i386 -I binary $(EMBED_KERNEL) -O elf32-i386 $@

rootfs.o: $(EMBED_ROOTFS)
	$(OBJCOPY) -B i386 -I binary $(EMBED_ROOTFS) -O elf32-i386 $@

ubnt_img.o: $(EMBED_UBNT_IMG)
	$(OBJCOPY) -B i386 -I binary $(EMBED_UBNT_IMG) -O elf32-i386 $@

$(AP51_RC).o: $(EMBED_KERNEL) $(EMBED_ROOTFS) $(EMBED_UBNT_IMG)
	$(WINDRES) -i $(AP51_RC) -I. -o $@

clean:
	rm -rf *.o *~ *.plg *.ncb libap51-flash.a ap51-flash ap51-flash-static ap51-flash.exe $(AP51_RC)

distclean: clean
	rm -rf $(EMBED_ROOTFS) $(EMBED_KERNEL) $(EMBED_UBNT_IMG)
