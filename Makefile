ROOT							?= $(CURDIR)
IBME_ROOT						?= $(ROOT)/lib
DEMO_ROOT						?= $(ROOT)/demo

.PHONY: all
all: build

.PHONY: build
build:
	$(MAKE) -C $(IBME_ROOT) \
		CROSS_COMPILE=$(CROSS_COMPILE) \
		PLATFORM=$(PLATFORM) \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)

.PHONY: install
install:
	mv $(IBME_ROOT)/ibme.a $(TA_DEV_KIT_DIR)/lib/. && \
	mkdir -p $(TA_DEV_KIT_DIR)/include/ibme && \
	cp $(IBME_ROOT)/include/* $(TA_DEV_KIT_DIR)/include/ibme/.

.PHONY: demo
demo:
	$(MAKE) -C $(DEMO_ROOT) \
		CROSS_COMPILE=$(CROSS_COMPILE) \
		TEEC_EXPORT=$(TEEC_EXPORT) \
		PLATFORM=$(PLATFORM) \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)

.PHONY: clean
clean:
	$(MAKE) -C $(IBME_ROOT) clean \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)

.PHONY: uninstall
uninstall:
	rm -r $(TA_DEV_KIT_DIR)/include/ibme; \
	rm $(TA_DEV_KIT_DIR)/lib/ibme.a;


.PHONY: demo_clean
demo_clean:
	$(MAKE) -C $(DEMO_ROOT) clean \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)