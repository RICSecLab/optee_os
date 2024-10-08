srcs-$(CFG_VERAISON_ATTESTATION_PTA) += remote_attestation.c
srcs-$(CFG_VERAISON_ATTESTATION_PTA) += cbor.c
srcs-$(CFG_VERAISON_ATTESTATION_PTA) += hash.c
srcs-$(CFG_VERAISON_ATTESTATION_PTA) += sign.c

cflags-y += -Wno-declaration-after-statement
cflags-y += -Wno-redundant-decls
