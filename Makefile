# 变量定义
BINARY_NAME=auto-tunnel
VERSION=1.0.0
# 默认架构为 amd64
ARCH?=amd64
BUILD_DIR=build
DEB_DIR=$(BUILD_DIR)/deb-$(ARCH)
RPM_DIR=$(BUILD_DIR)/rpm-$(ARCH)

# Go 相关变量
GOCMD=go
GOBUILD=$(GOCMD) build
GORUN=$(GOCMD) run
GOCLEAN=$(GOCMD) clean

# 打包相关变量
PACKAGE_NAME=${BINARY_NAME}
PACKAGE_VERSION=1.0.0
PACKAGE_MAINTAINER=AutoTunnel\ \<auto-tunnel@mageia.site\>
PACKAGE_DESCRIPTION=Auto\ SSH\ Tunnel\ Service
PACKAGE_RELEASE=1

# 安装路径
INSTALL_PATH=/usr/local/bin
CONFIG_PATH=/etc/auto-tunnel
SYSTEMD_PATH=/etc/systemd/system
LOG_PATH=/var/log/auto-tunnel

# 架构映射
RPM_ARCH=x86_64
DEB_ARCH=$(shell if [ "$(ARCH)" = "amd64" ]; then echo "amd64"; elif [ "$(ARCH)" = "arm64" ]; then echo "arm64"; else echo "$(ARCH)"; fi)

# 默认目标
.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "使用方法:"
	@echo "  make run         - 运行程序"
	@echo "  make build       - 构建程序"
	@echo "  make build-deb   - 构建 DEB 包"
	@echo "  make build-rpm   - 构建 RPM 包"
	@echo "  make build-tarball - 构建 tarball"
	@echo "  make clean       - 清理构建文件"
	@echo ""
	@echo "支持的架构:"
	@echo "  ARCH=amd64      - x86_64 架构"
	@echo "  ARCH=arm64      - ARM64/AArch64 架构"

.PHONY: run
run:
	$(GORUN) cmd/tunnel/main.go

.PHONY: build
build:
	@echo "Building ${BINARY_NAME} for linux-$(ARCH)..."
	mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=$(ARCH) $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-$(ARCH) cmd/tunnel/main.go

.PHONY: clean
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR) $(BINARY_NAME)

.PHONY: build-deb
build-deb: build
	@echo "Building DEB package for $(ARCH)..."
	mkdir -p $(DEB_DIR)/DEBIAN
	mkdir -p $(DEB_DIR)/usr/local/bin
	mkdir -p $(DEB_DIR)/etc/auto-tunnel
	mkdir -p $(DEB_DIR)/etc/systemd/system
	mkdir -p $(DEB_DIR)/var/log/auto-tunnel
	
	# 复制文件
	cp $(BUILD_DIR)/$(BINARY_NAME)-linux-$(ARCH) $(DEB_DIR)/usr/local/bin/$(BINARY_NAME)
	cp config.yaml.example $(DEB_DIR)/etc/auto-tunnel/config.yaml
	cp scripts/auto-tunnel.service $(DEB_DIR)/etc/systemd/system/
	
	# 创建 control 文件
	echo "Package: $(BINARY_NAME)" > $(DEB_DIR)/DEBIAN/control
	echo "Version: $(PACKAGE_VERSION)" >> $(DEB_DIR)/DEBIAN/control
	echo "Architecture: $(DEB_ARCH)" >> $(DEB_DIR)/DEBIAN/control
	echo "Maintainer: $(PACKAGE_MAINTAINER)" >> $(DEB_DIR)/DEBIAN/control
	echo "Description: $(PACKAGE_DESCRIPTION)" >> $(DEB_DIR)/DEBIAN/control
	
	# 创建 postinst 脚本
	echo "#!/bin/sh" > $(DEB_DIR)/DEBIAN/postinst
	echo "systemctl daemon-reload" >> $(DEB_DIR)/DEBIAN/postinst
	echo "systemctl enable auto-tunnel" >> $(DEB_DIR)/DEBIAN/postinst
	echo "systemctl start auto-tunnel" >> $(DEB_DIR)/DEBIAN/postinst
	chmod 755 $(DEB_DIR)/DEBIAN/postinst
	
	# 设置权限
	chmod 755 $(DEB_DIR)/usr/local/bin/$(BINARY_NAME)
	chmod 644 $(DEB_DIR)/etc/auto-tunnel/config.yaml
	chmod 644 $(DEB_DIR)/etc/systemd/system/auto-tunnel.service
	
	# 构建 deb 包，使用 gzip 压缩
	cd $(BUILD_DIR) && GZIP=-9 DEB_BUILD_OPTIONS=nocheck dpkg-deb -Zgzip --build deb-$(ARCH) "$(BINARY_NAME)_$(PACKAGE_VERSION)_$(DEB_ARCH).deb"

.PHONY: build-rpm
build-rpm: build
	@if [ "$(ARCH)" != "amd64" ]; then \
		echo "Error: RPM build is only supported for amd64 architecture"; \
		exit 1; \
	fi
	@echo "Building RPM package for amd64 (RPM_ARCH=$(RPM_ARCH))..."
	# 创建 RPM 构建目录结构
	mkdir -p $(RPM_DIR)/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	
	# 复制文件到 SOURCES，确保使用正确的源文件名和权限
	cp $(BUILD_DIR)/$(BINARY_NAME)-linux-$(ARCH) $(RPM_DIR)/SOURCES/$(BINARY_NAME)
	chmod 755 $(RPM_DIR)/SOURCES/$(BINARY_NAME)
	cp config.yaml.example $(RPM_DIR)/SOURCES/config.yaml
	chmod 644 $(RPM_DIR)/SOURCES/config.yaml
	cp scripts/auto-tunnel.service $(RPM_DIR)/SOURCES/auto-tunnel.service
	chmod 644 $(RPM_DIR)/SOURCES/auto-tunnel.service
	
	# 创建 spec 文件
	echo "Name: $(BINARY_NAME)" > $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "Version: $(PACKAGE_VERSION)" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "Release: $(PACKAGE_RELEASE)" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "Summary: $(PACKAGE_DESCRIPTION)" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "License: MIT" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "BuildArch: $(RPM_ARCH)" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "ExclusiveArch: $(RPM_ARCH)" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "AutoReqProv: no" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	# 使用 realpath 获取绝对路径，避免路径重复问题
	echo "%define _topdir $(shell realpath $(RPM_DIR))" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%define debug_package %{nil}" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%define __os_install_post %{nil}" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%define _build_id_links none" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%define _binary_payload w9.gzdio" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%define _source_payload w9.gzdio" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%define _binary_filedigest_algorithm 1" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%define _source_filedigest_algorithm 1" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%description" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "$(PACKAGE_DESCRIPTION)" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%prep" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%setup -q -c -T" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%install" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "mkdir -p %{buildroot}/usr/local/bin" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "mkdir -p %{buildroot}/etc/auto-tunnel" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "mkdir -p %{buildroot}/etc/systemd/system" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "mkdir -p %{buildroot}/var/log/auto-tunnel" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "install -D -m 755 %{_topdir}/SOURCES/$(BINARY_NAME) %{buildroot}/usr/local/bin/$(BINARY_NAME)" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "install -D -m 644 %{_topdir}/SOURCES/config.yaml %{buildroot}/etc/auto-tunnel/config.yaml" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "install -D -m 644 %{_topdir}/SOURCES/auto-tunnel.service %{buildroot}/etc/systemd/system/auto-tunnel.service" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%files" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%defattr(-,root,root,-)" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%attr(755,root,root) /usr/local/bin/$(BINARY_NAME)" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%config(noreplace) %attr(644,root,root) /etc/auto-tunnel/config.yaml" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%attr(644,root,root) /etc/systemd/system/auto-tunnel.service" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%dir %attr(755,root,root) /var/log/auto-tunnel" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "%post" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "systemctl daemon-reload" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "systemctl enable auto-tunnel" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "systemctl start auto-tunnel" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	echo "" >> $(RPM_DIR)/SPECS/$(BINARY_NAME).spec
	
	# 构建 RPM 包
	cd $(RPM_DIR) && rpmbuild -bb SPECS/$(BINARY_NAME).spec

.PHONY: build-tarball
build-tarball: build
	@echo "Building tarball for $(ARCH)..."
	mkdir -p $(BUILD_DIR)/$(BINARY_NAME)-$(PACKAGE_VERSION)-linux-$(ARCH)
	mkdir -p $(BUILD_DIR)/$(BINARY_NAME)-$(PACKAGE_VERSION)-linux-$(ARCH)/etc/auto-tunnel
	
	# 复制文件
	cp $(BUILD_DIR)/$(BINARY_NAME)-linux-$(ARCH) $(BUILD_DIR)/$(BINARY_NAME)-$(PACKAGE_VERSION)-linux-$(ARCH)/$(BINARY_NAME)
	cp config.yaml.example $(BUILD_DIR)/$(BINARY_NAME)-$(PACKAGE_VERSION)-linux-$(ARCH)/etc/auto-tunnel/config.yaml
	cp scripts/auto-tunnel.service $(BUILD_DIR)/$(BINARY_NAME)-$(PACKAGE_VERSION)-linux-$(ARCH)/auto-tunnel.service
	
	# 创建压缩包
	cd $(BUILD_DIR) && tar -czf $(BINARY_NAME)-$(PACKAGE_VERSION)-linux-$(ARCH).tar.gz $(BINARY_NAME)-$(PACKAGE_VERSION)-linux-$(ARCH)/
	rm -rf $(BUILD_DIR)/$(BINARY_NAME)-$(PACKAGE_VERSION)-linux-$(ARCH) 