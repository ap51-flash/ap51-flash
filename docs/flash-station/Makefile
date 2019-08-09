# SPDX-License-Identifier: GPL-3.0-or-later

include $(TOPDIR)/rules.mk

PKG_NAME:=ap51-flash
PKG_REV:=93
PKG_VERSION:=r$(PKG_REV)
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=svn
PKG_SOURCE_VERSION:=$(PKG_REV)
PKG_SOURCE_SUBDIR:=ap51-flash-$(PKG_VERSION)
PKG_SOURCE_URL:=http://dev.open-mesh.com/downloads/svn/ap51-flash/trunk
PKG_SOURCE:=$(PKG_SOURCE_SUBDIR).tar.gz

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/ap51-flash
  SECTION:=utils
  CATEGORY:=Utilities
  DEPENDS:=+libpcap
  TITLE:=A tool for flashing (nearly) all ap51/ap61 based routers
  URL:=http://dev.open-mesh.com
endef

define Package/ap51-flash/install
	$(INSTALL_DIR) $(1)/etc/config $(1)/etc/init.d $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ap51-flash $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/ap51-flash.init $(1)/etc/init.d/ap51-flash
	$(INSTALL_DATA) ./files/ap51-flash.conf $(1)/etc/config/ap51-flash
endef
#	install -m0755 -d $(1)/usr/sbin
#	install -m0755 $(PKG_BUILD_DIR)/ap51-flash $(1)/usr/sbin/
#	install -m0755 $(PKG_BUILD_DIR)/src/ifplugd $(1)/usr/sbin/

$(eval $(call BuildPackage,ap51-flash))
