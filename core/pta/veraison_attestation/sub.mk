srcs-$(CFG_VERAISON_ATTESTATION_PTA) += veraison_attestation.c
srcs-$(CFG_VERAISON_ATTESTATION_PTA) += cbor.c
srcs-$(CFG_VERAISON_ATTESTATION_PTA) += hash.c
srcs-$(CFG_VERAISON_ATTESTATION_PTA) += sign.c

cflags-y += -Wno-declaration-after-statement
cflags-y += -Wno-redundant-decls

ifeq ($(CFG_VERAISON_ATTESTATION_PTA_TEST_KEY),y)
cppflags-y += -DCFG_VERAISON_ATTESTATION_PTA_TEST_KEY
endif
