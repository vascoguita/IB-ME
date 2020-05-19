ROOT							?= $(CURDIR)

DEVEL_ROOT						?= $(ROOT)/..
TOOLCHAIN_ROOT					?= $(DEVEL_ROOT)/toolchains
AARCH64_PATH					?= $(TOOLCHAIN_ROOT)/aarch64
AARCH64_CROSS_COMPILE			?= $(AARCH64_PATH)/bin/aarch64-linux-gnu-
CROSS_COMPILE					?= $(AARCH64_CROSS_COMPILE)

OPTEE_OS_ROOT					?= $(DEVEL_ROOT)/optee_os
TA_DEV_KIT_DIR					?= $(OPTEE_OS_ROOT)/out/arm/export-ta_arm64

IBME_ROOT						?= $(ROOT)/lib
DEMO_ROOT						?= $(ROOT)/demo
PLATFORM						?= vexpress-qemu_armv8a
OPTEE_CLIENT_ROOT				?= $(DEVEL_ROOT)/optee_client
TEEC_EXPORT						?= $(OPTEE_CLIENT_ROOT)/out/export/usr

.PHONY: all
all: install-ibme

.PHONY: install-ibme
install-ibme: make-ibme
	mv $(IBME_ROOT)/ibme.a $(TA_DEV_KIT_DIR)/lib/. && \
	mkdir -p $(TA_DEV_KIT_DIR)/include/ibme && \
	cp $(IBME_ROOT)/include/* $(TA_DEV_KIT_DIR)/include/ibme/.

.PHONY: make-ibme
make-ibme:
	$(MAKE) -C $(IBME_ROOT) \
		CROSS_COMPILE=$(CROSS_COMPILE) \
		PLATFORM=$(PLATFORM) \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)

.PHONY: demo
demo: install-ibme
	$(MAKE) -C $(DEMO_ROOT) \
		CROSS_COMPILE=$(CROSS_COMPILE) \
		TEEC_EXPORT=$(TEEC_EXPORT) \
		PLATFORM=$(PLATFORM) \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)

.PHONY: clean
clean: ibme_clean demo_clean

.PHONY: ibme_clean
ibme_clean:
	rm -r $(TA_DEV_KIT_DIR)/include/ibme; \
	rm $(TA_DEV_KIT_DIR)/lib/ibme.a; \
	$(MAKE) -C $(IBME_ROOT) clean \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)

.PHONY: demo_clean
demo_clean:
	$(MAKE) -C $(DEMO_ROOT) clean \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)