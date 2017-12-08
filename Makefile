#
# Copyright (C) Marek Lindner
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
# SPDX-License-Identifier: GPL-3.0+
# License-Filename: LICENSES/preferred/GPL-3.0

# enable debug output
# EXTRA_CFLAGS += -DDEBUG
# clear screen after each subsequent flash
# EXTRA_CFLAGS += -DCLEAR_SCREEN

# define $EMBED_IMG=/path/to/image to have your image included
# into the binary where $EMBED_IMG is one of the following:
# * EMBED_CI
# * EMBED_CE
# * EMBED_UBNT
# * EMBED_UBOOT


ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	Q_CC = @echo '   ' CC $@;
	Q_LD = @echo '   ' LD $@;
	export Q_CC
	export Q_LD
endif
endif

BINARY_NAME = ap51-flash
OBJ += commandline.o
OBJ += flash.o
OBJ += fwcfg.o
OBJ += proto.o
OBJ += router_images.o
OBJ += router_redboot.o
OBJ += router_tftp_client.o
OBJ += router_tftp_server.o
OBJ += router_types.o
OBJ += socket.o
AP51_RC = ap51-flash-res

CC      = $(CROSS)gcc
STRIP   = $(CROSS)strip
OBJCOPY = $(CROSS)objcopy
WINDRES = $(CROSS)windres
COMPILE.c = $(Q_CC)$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
LINK.o = $(Q_LD)$(CC) $(CFLAGS) $(LDFLAGS) $(TARGET_ARCH)

ifeq ($(MAKECMDGOALS),$(BINARY_NAME))
	PLATFORM = LINUX
else ifeq ($(MAKECMDGOALS),$(BINARY_NAME).exe)
	LDFLAGS += -LWpdPack/Lib/
	LDLIBS += -lwpcap
	CFLAGS += -D_CONSOLE -D_MBCS -IWpdPack/Include/
	PLATFORM = WIN32
else ifeq ($(MAKECMDGOALS),$(BINARY_NAME)-osx)
	LDLIBS += -lpcap
	PLATFORM = OSX
endif

$(AP51_RC)::
	echo '#include "ap51-flash-res.h"' > $(AP51_RC)

ifneq ($(EMBED_CI)$(EMBED_CE)$(EMBED_UBNT)$(EMBED_UBOOT),)
ifeq ($(PLATFORM),WIN32)
OBJ += $(AP51_RC).o
endif

ifeq ($(PLATFORM),LINUX)
ifeq ($(OBJCP_OUT),)
	ifeq ($(shell getconf LONG_BIT),64)
		OBJCP_OUT = elf64-x86-64
	else
		OBJCP_OUT = elf32-i386
	endif
endif
endif
ifneq ($(DESC),)
	CFLAGS += -DEMBEDDED_DESC=\"$(DESC)\"
endif
endif

ifneq ($(EMBED_CI),)
	EMBED_CI_SYM = _binary_$(shell echo $(EMBED_CI) | sed 's@[-/.]@_@g')
	EMBED_O += img_ci.o
	CFLAGS += -DEMBED_CI
	OSX_EMBED_CFLAGS += -sectcreate __DATA _binary_img_ci $(EMBED_CI)
endif

ifneq ($(EMBED_CE),)
	EMBED_CE_SYM = _binary_$(shell echo $(EMBED_CE) | sed 's@[-/.]@_@g')
	EMBED_O += img_ce.o
	CFLAGS += -DEMBED_CE
	OSX_EMBED_CFLAGS += -sectcreate __DATA _binary_img_ce $(EMBED_CE)
endif

ifneq ($(EMBED_UBNT),)
	EMBED_UBNT_SYM = _binary_$(shell echo $(EMBED_UBNT) | sed 's@[-/.]@_@g')
	EMBED_O += img_ubnt.o
	CFLAGS += -DEMBED_UBNT
	OSX_EMBED_CFLAGS += -sectcreate __DATA _binary_img_ubnt $(EMBED_UBNT)
endif

ifneq ($(EMBED_UBOOT),)
	EMBED_UBOOT_SYM = _binary_$(shell echo $(EMBED_UBOOT) | sed 's@[-/.]@_@g')
	EMBED_O += img_uboot.o
	CFLAGS += -DEMBED_UBOOT
	OSX_EMBED_CFLAGS += -sectcreate __DATA _binary_img_uboot $(EMBED_UBOOT)
endif

CFLAGS += -Wall -Werror -W -g3 -std=gnu99 -Os -fno-strict-aliasing -D$(PLATFORM) -D_GNU_SOURCE $(EXTRA_CFLAGS) -MD -MP

NUM_CPUS = $(shell nproc 2> /dev/null || echo 1)

# try to generate revision
REVISION= $(shell	if [ -d .git ]; then \
				echo $$(git describe --always --dirty --match "v*" |sed 's/^v//' 2> /dev/null || echo "[unknown]"); \
			fi)
ifneq ($(REVISION),)
CPPFLAGS += -DSOURCE_VERSION=\"$(REVISION)\"
endif

# standard build rules
.SUFFIXES: .o .c
.c.o:
	$(COMPILE.c) -o $@ $<

all:
	$(MAKE) -j $(NUM_CPUS) $(BINARY_NAME)

$(BINARY_NAME): $(EMBED_O) $(OBJ)
	$(LINK.o) $^ $(LDLIBS) -o $@
	$(STRIP) $@

$(BINARY_NAME).exe: $(OBJ)
	$(LINK.o) $^ $(LDLIBS) -o $@
	$(STRIP) $@

$(BINARY_NAME)-osx: $(OBJ)
	$(LINK.o) $^ $(LDLIBS) $(OSX_EMBED_CFLAGS) -o $@
	$(STRIP) $@

$(OBJ): Makefile

ifeq ($(PLATFORM),LINUX)
img_ci.o:
	$(Q_CC)$(OBJCOPY) -B i386 -I binary $(EMBED_CI) -O $(OBJCP_OUT) \
	--redefine-sym $(EMBED_CI_SYM)_start=_binary_img_ci_start \
	--redefine-sym $(EMBED_CI_SYM)_end=_binary_img_ci_end \
	--redefine-sym $(EMBED_CI_SYM)_size=_binary_img_ci_size $@
else ifeq ($(PLATFORM),WIN32)
$(AP51_RC)::
	[ -z "$(EMBED_CI)" ] || echo 'IDR_CI_IMG RCDATA DISCARDABLE "$(EMBED_CI)"' >> $(AP51_RC)
endif

ifeq ($(PLATFORM),LINUX)
img_ce.o:
	$(Q_CC)$(OBJCOPY) -B i386 -I binary $(EMBED_CE) -O $(OBJCP_OUT) \
	--redefine-sym $(EMBED_CE_SYM)_start=_binary_img_ce_start \
	--redefine-sym $(EMBED_CE_SYM)_end=_binary_img_ce_end \
	--redefine-sym $(EMBED_CE_SYM)_size=_binary_img_ce_size $@
else ifeq ($(PLATFORM),WIN32)
$(AP51_RC)::
	[ -z "$(EMBED_CE)" ] || echo 'IDR_CE_IMG RCDATA DISCARDABLE "$(EMBED_CE)"' >> $(AP51_RC)
endif

ifeq ($(PLATFORM),LINUX)
img_ubnt.o:
	$(Q_CC)$(OBJCOPY) -B i386 -I binary $(EMBED_UBNT) -O $(OBJCP_OUT) \
	--redefine-sym $(EMBED_UBNT_SYM)_start=_binary_img_ubnt_start \
	--redefine-sym $(EMBED_UBNT_SYM)_end=_binary_img_ubnt_end \
	--redefine-sym $(EMBED_UBNT_SYM)_size=_binary_img_ubnt_size $@
else ifeq ($(PLATFORM),WIN32)
$(AP51_RC)::
	[ -z "$(EMBED_UBNT)" ] || echo 'IDR_UBNT_IMG RCDATA DISCARDABLE "$(EMBED_UBNT)"' >> $(AP51_RC)
endif

ifeq ($(PLATFORM),LINUX)
img_uboot.o:
	$(Q_CC)$(OBJCOPY) -B i386 -I binary $(EMBED_UBOOT) -O $(OBJCP_OUT) \
	--redefine-sym $(EMBED_UBOOT_SYM)_start=_binary_img_uboot_start \
	--redefine-sym $(EMBED_UBOOT_SYM)_end=_binary_img_uboot_end \
	--redefine-sym $(EMBED_UBOOT_SYM)_size=_binary_img_uboot_size $@
else ifeq ($(PLATFORM),WIN32)
$(AP51_RC)::
	[ -z "$(EMBED_UBOOT)" ] || echo 'IDR_UBOOT_IMG RCDATA DISCARDABLE "$(EMBED_UBOOT)"' >> $(AP51_RC)
endif

$(AP51_RC).o: $(AP51_RC)
	$(Q_CC)$(WINDRES) -i $(AP51_RC) -I. -o $@

clean:
	rm -rf *.o *.d *~ $(BINARY_NAME) $(BINARY_NAME).exe $(BINARY_NAME)-osx $(AP51_RC)

# load dependencies
DEP = $(OBJ:.o=.d)
-include $(DEP)

.PHONY: all clean
.DELETE_ON_ERROR:
.DEFAULT_GOAL := all
