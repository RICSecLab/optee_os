global-incdirs-y += inc
cflags-y += -Wno-declaration-after-statement
cflags-y += -Wno-redundant-decls
srcs-y += src/ieee754.c
srcs-y += src/qcbor_decode.c
srcs-y += src/qcbor_encode.c
srcs-y += src/qcbor_err_to_str.c
srcs-y += src/UsefulBuf.c
