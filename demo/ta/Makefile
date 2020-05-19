CFG_TEE_TA_LOG_LEVEL ?= 4
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

BINARY = 23e04a26-4960-43da-bb7f-73f38efb1f52

LDADD += $(TA_DEV_KIT_DIR)/lib/ibme.a
LDADD += $(TA_DEV_KIT_DIR)/lib/pbc.a
LDADD += $(TA_DEV_KIT_DIR)/lib/libgmp.a

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
