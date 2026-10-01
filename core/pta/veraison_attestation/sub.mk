srcs-$(CFG_VERAISON_ATTESTATION_PTA) += veraison_attestation.c
srcs-$(CFG_VERAISON_ATTESTATION_PTA) += cbor.c
srcs-$(CFG_VERAISON_ATTESTATION_PTA) += hash.c
srcs-$(CFG_VERAISON_ATTESTATION_PTA) += sign.c
ifeq ($(CFG_VERAISON_ATTESTATION_PTA_PLATFORM_CLAIMS),y)
srcs-$(CFG_IMX_OCOTP) += platform_imx.c
endif

cflags-$(CFG_VERAISON_ATTESTATION_PTA) += -Wno-declaration-after-statement
cflags-$(CFG_VERAISON_ATTESTATION_PTA) += -Wno-redundant-decls
