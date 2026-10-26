#
# Copyright (C) 2026 tachyon-core developers
#
# This is free software, licensed under the GNU General Public License v3.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=xrust
PKG_VERSION:=0.0.1
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/Screamshow/xrust.git
PKG_SOURCE_DATE:=2026-10-09

PKG_LICENSE:=GPL-3.0-only
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Dushnilin

PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/xrust/Default
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=High-performance pure-Rust proxy core (sing-box compatible)
  URL:=https://github.com/Screamshow/xrust
  DEPENDS:=+ca-bundle +kmod-nft-tproxy +kmod-tun +ip-full
endef

define Package/xrust
$(call Package/xrust/Default)
  TITLE+= (Pure-Rust router edition)
  PROVIDES:=sing-box
endef

define Package/xrust/description
 Xrust is a pure-Rust, zero-C-crypto proxy core for OpenWrt routers.
 It provides 100% sing-box compatibility with native CLI drop-in support,
 Clash REST API, transparent proxy (TProxy and TUN), and comprehensive
 protocol support (VLESS, VMess, Reality, Shadowsocks, WireGuard/AmneziaWG,
 Trojan, Hysteria2, TUIC, and direct steering).
endef

define Build/Compile/xrust
	cargo build --release --target $(RUSTC_TARGET_ARCH)-unknown-linux-musl --bin xrust
endef

define Package/xrust/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/$(RUSTC_TARGET_ARCH)-unknown-linux-musl/release/xrust $(1)/usr/bin/xrust
	$(LN) xrust $(1)/usr/bin/sing-box

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/xrust.init $(1)/etc/init.d/xrust
	$(LN) xrust $(1)/etc/init.d/sing-box

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/xrust.config $(1)/etc/config/xrust

	$(INSTALL_DIR) $(1)/etc/xrust
	$(INSTALL_DATA) ./files/config.json $(1)/etc/xrust/config.json
endef

$(eval $(call BuildPackage,xrust))
