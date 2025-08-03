#!/usr/bin/make -f

include ../scripts/check.mk

PACKER ?= packer
PACKER_LOG ?= 0
export PACKER_LOG

ISO ?=
VHDX ?=
VERSION ?= 2022
HEADLESS ?= false
TIMEOUT ?= 1h
TEMPLATE ?= http/Autounattend.xml.${FORMAT}.template
BUILD_ID ?= build-$(shell date +%Y%m%d-%H%M%S)

ifeq ($(strip $(VERSION)),10)
	TYPE = Windows
	EDIT ?= PRO
else ifeq ($(strip $(VERSION)),11)
	TYPE = Windows
	EDIT ?= PRO
	USE_TPM ?= yes
else ifeq ($(strip $(VERSION)),2025)
	TYPE = Windows Server
	EDIT ?= SERVERSTANDARD
else ifeq ($(strip $(VERSION)),HCI)
	TEMPLATE = http/Autounattend.xml.HCI.template
else
	TYPE = Windows Server
	EDIT ?= SERVERSTANDARD
endif

ifneq ($(strip $(VHDX)),)
	FORMAT := VHDX
else
	FORMAT := ISO
endif

ifeq ($(wildcard /usr/share/OVMF/OVMF_CODE.fd),)
	OVMF_SFX ?= _4M
else
	OVMF_SFX ?=
endif

.PHONY: all clean clean-downloads clean-all

all: windows

$(eval $(call check_packages_deps,cloud-image-utils,genisoimage,swtpm ovmf,cloud-image-utils ovmf,genisoimage,swtpm,ntfs-3g))

OVMF_VARS.fd: /usr/share/OVMF/OVMF_VARS*.ms.fd
	cp -v $< $@

http/Autounattend.xml: ${TEMPLATE}
	echo "Using ${TEMPLATE}..."
	sed s#@VERSION@#"${TYPE} ${VERSION} ${EDIT}"#g $< > $@
ifneq ($(strip $(PKEY)),)
	sed -i s#@PKEY@#${PKEY}#g $@
	sed -i 's/<!--<ProductKey>/<ProductKey>/;s/<\/ProductKey>-->/<\/ProductKey>/' $@
endif
ifeq ($(strip $(VERSION)),10)
	sed -i 's/<!--<LocalAccounts>/<LocalAccounts>/;s/<\/LocalAccounts>-->/<\/LocalAccounts>/' $@
else ifeq ($(strip $(VERSION)),11)
	sed -i 's/<!--<LocalAccounts>/<LocalAccounts>/;s/<\/LocalAccounts>-->/<\/LocalAccounts>/' $@
endif

http/downloads:
	mkdir -p http/downloads

# Individual download targets with conditional logic
http/downloads/wdksetup.exe: http/downloads
	test -s $@ || curl -L "https://download.microsoft.com/download/8/6/9/86925F0F-D57A-4BA4-8278-861B6876D78E/wdk/wdksetup.exe" -o $@

http/downloads/CloudbaseInitSetup_Stable_x64.msi: http/downloads
	test -s $@ || curl -L "https://cloudbase.it/downloads/CloudbaseInitSetup_Stable_x64.msi" -o $@

http/downloads/virtio-win-gt-x64.msi: http/downloads
	test -s $@ || curl -L "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win-gt-x64.msi" -o $@

http/downloads/virtio-win-guest-tools.exe: http/downloads
	test -s $@ || curl -L "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win-guest-tools.exe" -o $@

downloads: http/downloads/wdksetup.exe http/downloads/CloudbaseInitSetup_Stable_x64.msi http/downloads/virtio-win-gt-x64.msi http/downloads/virtio-win-guest-tools.exe
	mkisofs -o downloads.iso -V 'Downloads' -input-charset utf-8 -r -J http/downloads

extra_drivers:
	mkisofs -o drivers.iso -V 'Extra Drivers' -input-charset utf-8 -r -J drivers

.INTERMEDIATE: extra_drivers http/Autounattend.xml downloads

windows: check-deps clean extra_drivers downloads http/Autounattend.xml OVMF_VARS.fd
	@echo "Starting log server for build: ${BUILD_ID}"
	@mkdir -p build_logs
	@python3 scripts/log_server.py 8080 & echo $$! > /tmp/log_server.pid
	@sleep 2
	@echo "Log server started (PID: $$(cat /tmp/log_server.pid))"
ifeq ($(strip $(VERSION)),11)
	mkdir -p /tmp/swtpm; \
	swtpm socket --daemon --tpm2 --tpmstate dir=/tmp/swtpm --ctrl type=unixio,path=/tmp/swtpm/swtpm-sock --log level=10
endif
ifneq ($(strip $(VHDX)),)
	qemu-img convert -p -O raw ${VHDX} windows_builder.img; \
	scripts/setup-nbd windows_builder.img; \
	TMP_DIR=$$(mktemp -d /tmp/packer-maas-XXXX); \
	nbd=$$(cat /tmp/nbd.lock); \
	pnum=$$(lsblk -l $${nbd} | grep -c part); \
	echo 'Adding unattend.xml to image...'; \
	mount -t ntfs $${nbd}p$${pnum} $${TMP_DIR}; \
	mkdir -pv $${TMP_DIR}/Windows/Panther/; \
	cp -v ./http/Autounattend.xml $${TMP_DIR}/Windows/Panther/unattend.xml; \
	sync -f $${TMP_DIR}/Windows/Panther/; \
	umount $${TMP_DIR}; \
	qemu-nbd -d $${nbd}; \
	rmdir $${TMP_DIR};
	BUILD_ID=${BUILD_ID} ${PACKER} init . && BUILD_ID=${BUILD_ID} ${PACKER} build -var iso_path=windows_builder.img \
			-var headless=${HEADLESS} \
			-var ovmf_suffix=${OVMF_SFX} \
			-var timeout=${TIMEOUT} \
			-var is_vhdx=true \
			-var disk_size=64G \
			windows.pkr.hcl; \
	BUILD_EXIT_CODE=$$?; \
	if [ -f /tmp/log_server.pid ]; then \
		echo "Stopping log server (PID: $$(cat /tmp/log_server.pid))..."; \
		kill $$(cat /tmp/log_server.pid) 2>/dev/null || true; \
		rm -f /tmp/log_server.pid; \
	fi; \
	exit $$BUILD_EXIT_CODE
else
	BUILD_ID=${BUILD_ID} ${PACKER} init . && BUILD_ID=${BUILD_ID} ${PACKER} build -var iso_path=${ISO} \
			-var headless=${HEADLESS} \
			-var ovmf_suffix=${OVMF_SFX} \
			-var is_vhdx=false \
			-var timeout=${TIMEOUT} \
			-var use_tpm=${USE_TPM} \
			windows.pkr.hcl; \
	BUILD_EXIT_CODE=$$?; \
	if [ -f /tmp/log_server.pid ]; then \
		echo "Stopping log server (PID: $$(cat /tmp/log_server.pid))..."; \
		kill $$(cat /tmp/log_server.pid) 2>/dev/null || true; \
		rm -f /tmp/log_server.pid; \
	fi; \
	exit $$BUILD_EXIT_CODE
endif

clean:
	${RM} -rf output-* windows.dd.gz http/Autounattend.xml \
	drivers.iso downloads.iso windows_builder.img OVMF_VARS.fd
	@if [ -f /tmp/log_server.pid ]; then \
		echo "Stopping any running log server..."; \
		kill $$(cat /tmp/log_server.pid) 2>/dev/null || true; \
		rm -f /tmp/log_server.pid; \
	fi

clean-downloads:
	${RM} -rf http/downloads downloads.iso

clean-all: clean clean-downloads
