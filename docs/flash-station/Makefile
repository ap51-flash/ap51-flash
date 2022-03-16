# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: Linus Lüssing <linus.luessing@c0d3.blue>

include $(TOPDIR)/rules.mk

PKG_NAME:=ap51-flash
PKG_VERSION:=2019.0.1+20220316
PKG_RELEASE:=$(AUTORELEASE)

PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=ccd52e60cb68f24bdc8f4f74d26e7af78da98427
PKG_SOURCE_URL:=https://github.com/ap51-flash/ap51-flash.git
PKG_MIRROR_HASH=skip

PKG_MAINTAINER:=Russell Senior <russell@personaltelco.net>
PKG_LICENSE:=GPL-3.0-or-later CC0-1.0
PKG_LICENSE_FILES:=LICENSES/GPL-3.0-or-later.txt LICENSES/CC0-1.0.txt

include $(INCLUDE_DIR)/package.mk

define Package/ap51-flash
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=A tool for flashing (nearly) all ap51/ap61 based routers
  URL:=https://ap51-flash.readthedocs.io/en/latest/
endef

# pass optimization flags
MAKE_FLAGS += \
	REVISION="$(PKG_VERSION)" \
	ap51-flash

TARGET_CFLAGS += -flto
TARGET_LDFLAGS += -Wl,--gc-sections,--as-needed

define Package/ap51-flash/install
	$(INSTALL_DIR) $(1)/etc/config $(1)/etc/init.d $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ap51-flash $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/ap51-flash.init $(1)/etc/init.d/ap51-flash
	$(INSTALL_DATA) ./files/ap51-flash.config $(1)/etc/config/ap51-flash
endef

define Package/ap51-flash/conffiles
/etc/config/ap51-flash
endef

$(eval $(call BuildPackage,ap51-flash))
