# ==============================================================================
# Verum Cryptographic Suite - Unified Release Compilation Flags & Matrix Defs
# ==============================================================================
# Single source of truth for both CMake (via include()) and Python build scripts.
# All libraries are compiled with strict deterministic safety-critical options.
# ==============================================================================

set(PROJECT_WARNINGS
    -Wall
    -Wextra
    -Werror
    -pedantic
    -Waddress
    -Warray-bounds
    -Wcast-align
    -Wcast-qual
    -Wbad-function-cast
    -Wconversion
    -Wdouble-promotion
    -Wformat=2
    -Wimplicit-function-declaration
    -Wimplicit-fallthrough
    -Wmissing-declarations
    -Wmissing-prototypes
    -Wmissing-variable-declarations
    -Wnull-dereference
    -Wpointer-arith
    -Wreserved-identifier
    -Wsign-compare
    -Wstrict-aliasing
    -Wstrict-overflow=2
    -Wstrict-prototypes
    -Wswitch-default
    -Wswitch-enum
    -Wundef
    -Wuninitialized
    -Wunused-macros
    -Wunused-variable
    -Wvla
    -Wfloat-equal
    -Wcomma
    -Wassign-enum
    -Wshadow-all
    -Wunreachable-code-aggressive
    -Wunreachable-code
    -Wcast-function-type
    -Wmissing-noreturn
    -Wold-style-definition
    -Wdisabled-macro-expansion
    -Wextra-semi
    -Wnewline-eof
    -Wshift-sign-overflow
    -Wloop-analysis
)

set(PROJECT_COMPILE_OPTIONS
    -std=c11
    -fno-gnu-keywords
    -fsigned-char
    -fno-short-enums
    -fno-strict-aliasing
    -fwrapv
    -fno-delete-null-pointer-checks
    -fno-strict-overflow
    -ffp-contract=off
    -fno-fast-math
    -fno-finite-math-only
    -fno-unsafe-math-optimizations
    -fno-associative-math
    -fno-reciprocal-math
    -fsigned-zeros
    -fno-common
    -fno-exceptions
    -fno-unwind-tables
    -fno-asynchronous-unwind-tables
    -fdiagnostics-show-option
    -ferror-limit=0
    -fmacro-backtrace-limit=0
)

set(PROJECT_BASE_FLAGS
    -O0
)

# 24 Explicit Ascon Matrix Configurations (12 Standard + 12 FIPS 140-3)
set(MATRIX_CONFIG_NAMES
    ad_direct_unrolled
    ad_direct_memory
    ad_interleaved_unrolled
    ad_interleaved_memory
    ad_preinterleaved_unrolled
    ad_preinterleaved_memory
    noad_direct_unrolled
    noad_direct_memory
    noad_interleaved_unrolled
    noad_interleaved_memory
    noad_preinterleaved_unrolled
    noad_preinterleaved_memory
    fips_ad_direct_unrolled
    fips_ad_direct_memory
    fips_ad_interleaved_unrolled
    fips_ad_interleaved_memory
    fips_ad_preinterleaved_unrolled
    fips_ad_preinterleaved_memory
    fips_noad_direct_unrolled
    fips_noad_direct_memory
    fips_noad_interleaved_unrolled
    fips_noad_interleaved_memory
    fips_noad_preinterleaved_unrolled
    fips_noad_preinterleaved_memory
)

set(DEFS_ad_direct_unrolled
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    -DVERUM_ASCON_LOOP_UNROLL_MERGED_DEF
)

set(DEFS_ad_direct_memory
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    -DVERUM_OPTIMIZATION_MEMORY_DEF
)

set(DEFS_ad_interleaved_unrolled
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    -DVERUM_ASCON_BIT_INTERLEAVING_DEF
    -DVERUM_ASCON_LOOP_UNROLL_MERGED_DEF
)

set(DEFS_ad_interleaved_memory
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    -DVERUM_ASCON_BIT_INTERLEAVING_DEF
    -DVERUM_OPTIMIZATION_MEMORY_DEF
)

set(DEFS_ad_preinterleaved_unrolled
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    -DVERUM_ASCON_BIT_INTERLEAVING_DEF
    -DVERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    -DVERUM_ASCON_LOOP_UNROLL_MERGED_DEF
)

set(DEFS_ad_preinterleaved_memory
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    -DVERUM_ASCON_BIT_INTERLEAVING_DEF
    -DVERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    -DVERUM_OPTIMIZATION_MEMORY_DEF
)

set(DEFS_noad_direct_unrolled
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_ASCON_LOOP_UNROLL_MERGED_DEF
)

set(DEFS_noad_direct_memory
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_OPTIMIZATION_MEMORY_DEF
)

set(DEFS_noad_interleaved_unrolled
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_ASCON_BIT_INTERLEAVING_DEF
    -DVERUM_ASCON_LOOP_UNROLL_MERGED_DEF
)

set(DEFS_noad_interleaved_memory
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_ASCON_BIT_INTERLEAVING_DEF
    -DVERUM_OPTIMIZATION_MEMORY_DEF
)

set(DEFS_noad_preinterleaved_unrolled
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_ASCON_BIT_INTERLEAVING_DEF
    -DVERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    -DVERUM_ASCON_LOOP_UNROLL_MERGED_DEF
)

set(DEFS_noad_preinterleaved_memory
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_ASCON_BIT_INTERLEAVING_DEF
    -DVERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    -DVERUM_OPTIMIZATION_MEMORY_DEF
)

# ------------------------------------------------------------------------------
# 12 FIPS 140-3 Compliant Configurations (includes -DVERUM_STANDARD_FIPS_140_3_DEF)
# ------------------------------------------------------------------------------

set(DEFS_fips_ad_direct_unrolled
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_STANDARD_FIPS_140_3_DEF
    -DVERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    -DVERUM_ASCON_LOOP_UNROLL_MERGED_DEF
)

set(DEFS_fips_ad_direct_memory
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_STANDARD_FIPS_140_3_DEF
    -DVERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    -DVERUM_OPTIMIZATION_MEMORY_DEF
)

set(DEFS_fips_ad_interleaved_unrolled
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_STANDARD_FIPS_140_3_DEF
    -DVERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    -DVERUM_ASCON_BIT_INTERLEAVING_DEF
    -DVERUM_ASCON_LOOP_UNROLL_MERGED_DEF
)

set(DEFS_fips_ad_interleaved_memory
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_STANDARD_FIPS_140_3_DEF
    -DVERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    -DVERUM_ASCON_BIT_INTERLEAVING_DEF
    -DVERUM_OPTIMIZATION_MEMORY_DEF
)

set(DEFS_fips_ad_preinterleaved_unrolled
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_STANDARD_FIPS_140_3_DEF
    -DVERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    -DVERUM_ASCON_BIT_INTERLEAVING_DEF
    -DVERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    -DVERUM_ASCON_LOOP_UNROLL_MERGED_DEF
)

set(DEFS_fips_ad_preinterleaved_memory
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_STANDARD_FIPS_140_3_DEF
    -DVERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    -DVERUM_ASCON_BIT_INTERLEAVING_DEF
    -DVERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    -DVERUM_OPTIMIZATION_MEMORY_DEF
)

set(DEFS_fips_noad_direct_unrolled
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_STANDARD_FIPS_140_3_DEF
    -DVERUM_ASCON_LOOP_UNROLL_MERGED_DEF
)

set(DEFS_fips_noad_direct_memory
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_STANDARD_FIPS_140_3_DEF
    -DVERUM_OPTIMIZATION_MEMORY_DEF
)

set(DEFS_fips_noad_interleaved_unrolled
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_STANDARD_FIPS_140_3_DEF
    -DVERUM_ASCON_BIT_INTERLEAVING_DEF
    -DVERUM_ASCON_LOOP_UNROLL_MERGED_DEF
)

set(DEFS_fips_noad_interleaved_memory
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_STANDARD_FIPS_140_3_DEF
    -DVERUM_ASCON_BIT_INTERLEAVING_DEF
    -DVERUM_OPTIMIZATION_MEMORY_DEF
)

set(DEFS_fips_noad_preinterleaved_unrolled
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_STANDARD_FIPS_140_3_DEF
    -DVERUM_ASCON_BIT_INTERLEAVING_DEF
    -DVERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    -DVERUM_ASCON_LOOP_UNROLL_MERGED_DEF
)

set(DEFS_fips_noad_preinterleaved_memory
    -DVERUM_CUSTOM_CONFIG
    -DVERUM_STANDARD_FIPS_140_3_DEF
    -DVERUM_ASCON_BIT_INTERLEAVING_DEF
    -DVERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    -DVERUM_OPTIMIZATION_MEMORY_DEF
)
