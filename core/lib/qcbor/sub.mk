global-incdirs-y += inc

cflags-y += -Wno-declaration-after-statement
cflags-y += -Wno-redundant-decls
cppflags-y += -DQCBOR_DISABLE_FLOAT_HW_USE

# Floating-point operations are used in ieee754.c, and the use of
# -mgeneral-regs-only is incompatible with floating-point types.
# Therefore, we remove the -mgeneral-regs-only flag to allow
# floating-point instructions and avoid compilation errors.
cflags-remove-y += -mgeneral-regs-only

srcs-y += src/ieee754.c
srcs-y += src/qcbor_decode.c
srcs-y += src/qcbor_encode.c
srcs-y += src/qcbor_err_to_str.c
srcs-y += src/UsefulBuf.c
