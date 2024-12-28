# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: Marek Lindner <marek.lindner@mailbox.org>
# SPDX-FileCopyrightText: Sven Eckelmann <sven@narfation.org>

$(AP51_RC):: Makefile
	$(Q_SILENT)echo '#include "ap51-flash-res.h"' > $(AP51_RC)

ifneq ($(filter-out ,$(EMBEDDED_IMAGES)),)
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
  CPPFLAGS += -DEMBEDDED_DESC=\"$(DESC)\"
endif
endif

# automatically generate embedding images via:
# $(call embed_image,TYPE_UPPER,TYPE_LOWER))
define embed_image

ifneq ($(EMBED_$(1)),)
  EMBED_$(1)_SYM = _binary_$(shell echo $(EMBED_$(1)) | sed 's@[-/.]@_@g')
  CPPFLAGS += -DEMBED_$(1)

ifeq ($(PLATFORM),LINUX)
  OBJ += img_$(2).o

img_$(2).o: $(EMBED_$(1))
	$(Q_CC)$(OBJCOPY) -B i386 -I binary $(EMBED_$(1)) -O $(OBJCP_OUT) \
	--redefine-sym $$(EMBED_$(1)_SYM)_start=_binary_img_$(2)_start \
	--redefine-sym $$(EMBED_$(1)_SYM)_end=_binary_img_$(2)_end \
	--strip-symbol $$(EMBED_$(1)_SYM)_size img_$(2).o
else ifeq ($(PLATFORM),WIN32)
$(AP51_RC):: $(EMBED_$(1))
	$(Q_SILENT)[ -z "$(EMBED_$(1))" ] || echo 'IDR_$(1)_IMG RCDATA DISCARDABLE "$(EMBED_$(1))"' >> $(AP51_RC)
else ifeq ($(PLATFORM),OSX)
  LDFLAGS += -sectcreate __DATA _binary_img_$(2) $(EMBED_$(1))
endif

endif

endef # embed_image
