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
# CPPFLAGS += -DDEBUG
# clear screen after each subsequent flash
# CPPFLAGS += -DCLEAR_SCREEN

# define $EMBED_IMG=/path/to/image to have your image included
# into the binary where $EMBED_IMG is one of the following:
# * EMBED_CI
# * EMBED_CE
# * EMBED_UBNT
# * EMBED_UBOOT

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

BINARY_TARGET_NAMES += $(BINARY_NAME)
BINARY_TARGET_NAMES += $(BINARY_NAME).exe
BINARY_TARGET_NAMES += $(BINARY_NAME)-osx

# ap51-flash flags and options
CFLAGS += -Wall -W -std=gnu99 -fno-strict-aliasing $(EXTRA_CFLAGS) -MD -MP
CPPFLAGS += -D_GNU_SOURCE
LDLIBS +=

# disable verbose output
ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
  Q_CC = @echo '   ' CC $@;
  Q_LD = @echo '   ' LD $@;
  Q_SILENT = @
  export Q_CC
  export Q_LD
  export Q_SILENT
endif
endif

CC      = $(CROSS)gcc
RM     ?= rm -f
STRIP   = $(CROSS)strip
OBJCOPY = $(CROSS)objcopy
WINDRES = $(CROSS)windres
COMPILE.c = $(Q_CC)$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
LINK.o = $(Q_LD)$(CC) $(CFLAGS) $(LDFLAGS) $(TARGET_ARCH)

ifeq ($(MAKECMDGOALS),)
  PLATFORM = LINUX
else ifeq ($(MAKECMDGOALS),$(BINARY_NAME))
  PLATFORM = LINUX
else ifeq ($(MAKECMDGOALS),$(BINARY_NAME).exe)
  PLATFORM = WIN32
else ifeq ($(MAKECMDGOALS),$(BINARY_NAME)-osx)
  PLATFORM = OSX
endif

ifneq ($(PLATFORM),)
CPPFLAGS += -D$(PLATFORM)
endif

ifeq ($(PLATFORM),LINUX)
  BINARY_SUFFIX =
else ifeq ($(PLATFORM),WIN32)
  BINARY_SUFFIX = .exe
  CPPFLAGS += -D_CONSOLE -D_MBCS -IWpdPack/Include/
  LDFLAGS += -LWpdPack/Lib/
  LDLIBS += -lwpcap
else ifeq ($(PLATFORM),OSX)
  BINARY_SUFFIX = -osx
  LDLIBS += -lpcap
endif

EMBEDDED_IMAGES += $(EMBED_CI)
EMBEDDED_IMAGES += $(EMBED_CE)
EMBEDDED_IMAGES += $(EMBED_UBNT)
EMBEDDED_IMAGES += $(EMBED_UBOOT)

Makefile: embed_image.mk
include embed_image.mk

$(eval $(call embed_image,CI,ci))
$(eval $(call embed_image,CE,ce))
$(eval $(call embed_image,UBNT,ubnt))
$(eval $(call embed_image,UBOOT,uboot))

# try to generate revision
REVISION= $(shell \
  if [ -d .git ]; then \
    echo $$(git describe --always --dirty --match "v*" |sed 's/^v//' 2> /dev/null || echo "[unknown]"); \
  fi)
ifneq ($(REVISION),)
CPPFLAGS += -DSOURCE_VERSION=\"$(REVISION)\"
endif

# standard build rules
.SUFFIXES: .o .c
.c.o:
	$(COMPILE.c) -o $@ $<

all: $(BINARY_NAME)$(BINARY_SUFFIX)

$(BINARY_TARGET_NAMES): $(OBJ)
	$(LINK.o) $^ $(LDLIBS) -o $@
	$(STRIP) $@

$(OBJ): Makefile

$(AP51_RC).o: $(AP51_RC)
	$(Q_CC)$(WINDRES) -i $(AP51_RC) -I. -o $@

clean:
	$(RM) *.o *.d *~ $(BINARY_TARGET_NAMES) $(AP51_RC)

# load dependencies
DEP = $(OBJ:.o=.d)
-include $(DEP)

.PHONY: all clean
.DELETE_ON_ERROR:
.DEFAULT_GOAL := all
