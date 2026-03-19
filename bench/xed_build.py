"""CFFI out-of-line build script for Intel XED bindings."""

import os

import cffi

xed_include = os.environ.get("XED_INCLUDE_DIR", "/root/xedkit/include")
xed_libdir = os.environ.get("XED_LIB_DIR", "/root/xedkit/lib")

ffi = cffi.FFI()

ffi.cdef("""
    // Opaque types — CFFI computes correct sizes at compile time
    typedef struct { ...; } xed_state_t;
    typedef struct { ...; } xed_decoded_inst_t;
    typedef int xed_error_enum_t;
    typedef int xed_machine_mode_enum_t;
    typedef int xed_address_width_enum_t;

    // Constants — resolved from headers at compile time
    #define XED_MACHINE_MODE_LEGACY_32 ...
    #define XED_MACHINE_MODE_LONG_64 ...
    #define XED_ADDRESS_WIDTH_32b ...
    #define XED_ADDRESS_WIDTH_64b ...
    #define XED_ERROR_NONE ...
    #define XED_SYNTAX_INTEL ...

    // Opaque types for operand introspection
    typedef struct { ...; } xed_inst_t;
    typedef struct { ...; } xed_operand_t;
    typedef int xed_operand_enum_t;
    typedef int xed_operand_action_enum_t;
    typedef int xed_reg_enum_t;

    // Register operand slot constants
    #define XED_OPERAND_REG0 ...
    #define XED_OPERAND_REG1 ...
    #define XED_OPERAND_REG2 ...
    #define XED_OPERAND_REG3 ...
    #define XED_OPERAND_REG4 ...
    #define XED_OPERAND_REG5 ...
    #define XED_OPERAND_REG6 ...
    #define XED_OPERAND_REG7 ...
    #define XED_OPERAND_REG8 ...

    // Operand action constants (write-related)
    #define XED_OPERAND_ACTION_RW ...
    #define XED_OPERAND_ACTION_W ...
    #define XED_OPERAND_ACTION_RCW ...
    #define XED_OPERAND_ACTION_CW ...

    // Register constant
    #define XED_REG_INVALID ...

    void xed_tables_init(void);
    void xed_state_init2(xed_state_t*, xed_machine_mode_enum_t, xed_address_width_enum_t);
    void xed_decoded_inst_zero_set_mode(xed_decoded_inst_t*, const xed_state_t*);
    xed_error_enum_t xed_decode(xed_decoded_inst_t*, const uint8_t*, unsigned int);
    unsigned int xed_decoded_inst_get_length(const xed_decoded_inst_t*);
    const char* xed_error_enum_t2str(xed_error_enum_t);
    int xed_format_context(int, const xed_decoded_inst_t*, char*, int, uint64_t, void*, void*);

    // Operand introspection
    const xed_inst_t* xed_decoded_inst_inst(const xed_decoded_inst_t*);
    unsigned int xed_inst_noperands(const xed_inst_t*);
    const xed_operand_t* xed_inst_operand(const xed_inst_t*, unsigned int);
    xed_operand_enum_t xed_operand_name(const xed_operand_t*);
    xed_operand_action_enum_t xed_operand_rw(const xed_operand_t*);
    xed_reg_enum_t xed_decoded_inst_get_reg(const xed_decoded_inst_t*, xed_operand_enum_t);
    const char* xed_reg_enum_t2str(xed_reg_enum_t);
""")

ffi.set_source(
    "_xed_cffi",
    '#include <xed/xed-interface.h>',
    libraries=["xed"],
    include_dirs=[xed_include],
    library_dirs=[xed_libdir],
)

if __name__ == "__main__":
    ffi.compile()
