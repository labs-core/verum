cmake_minimum_required(VERSION 3.25)

# =============================================================================
# Force Clang before project()
# =============================================================================

set(CMAKE_C_COMPILER clang)

find_program(LLVM_AR     NAMES llvm-ar)
find_program(LLVM_RANLIB NAMES llvm-ranlib)
find_program(LLVM_NM     NAMES llvm-nm)

if(LLVM_AR)
    set(CMAKE_AR "${LLVM_AR}")
endif()

if(LLVM_RANLIB)
    set(CMAKE_RANLIB "${LLVM_RANLIB}")
endif()

if(LLVM_NM)
    set(CMAKE_NM "${LLVM_NM}")
endif()

project(VERUM
    VERSION     0.1.0
    LANGUAGES   C
    DESCRIPTION "Cryptographic primitives suite for mission-critical and safety-critical software"
)
# =============================================================================
# Paths
# =============================================================================

set(SOURCE_DIR  ${CMAKE_SOURCE_DIR}/source)
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(TEST_DIR    ${CMAKE_SOURCE_DIR}/test)
set(UNITY_DIR   ${TEST_DIR}/unity)

# =============================================================================
# Sources
# =============================================================================

file(GLOB_RECURSE SOURCES_C   CONFIGURE_DEPENDS ${SOURCE_DIR}/*.c)
file(GLOB_RECURSE HEADERS     CONFIGURE_DEPENDS ${INCLUDE_DIR}/*.h)
file(GLOB_RECURSE TEST_SRCS_C CONFIGURE_DEPENDS ${TEST_DIR}/*.c)

if(NOT SOURCES_C)
    message(FATAL_ERROR "No .c files found under ${SOURCE_DIR}")
endif()
if(NOT TEST_SRCS_C)
    message(WARNING "No .c files found under ${TEST_DIR} — test_runner will be empty")
endif()

# =============================================================================
# Flags
# =============================================================================

set(PROJECT_WARNINGS
    -Wall -Wextra -Werror -pedantic
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
    -Wshadow
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
)

# -DENABLE_G3=ON (default) → -g3   full macro debug info
# -DENABLE_G3=OFF          → -g    standard debug info
option(ENABLE_G3 "Use -g3 instead of -g" ON)
set(DEBUG_INFO_FLAG $<IF:$<BOOL:${ENABLE_G3}>,-g3,-g>)

set(PROJECT_BASE_FLAGS  -O0 ${DEBUG_INFO_FLAG})
set(SANITIZE_FLAGS      -fsanitize=address,undefined)

# =============================================================================
# Production objects
# =============================================================================

add_library(verum OBJECT ${SOURCES_C})

target_include_directories(verum PUBLIC ${INCLUDE_DIR})

target_compile_options(verum PRIVATE
    ${PROJECT_BASE_FLAGS}
    ${PROJECT_WARNINGS}
    $<$<CONFIG:Debug>:${SANITIZE_FLAGS}>
)

target_compile_definitions(verum PRIVATE
    $<$<CONFIG:Debug>:DEBUG>
)

# Consumers that link verum in Debug inherit the sanitiser link flags.
target_link_options(verum INTERFACE
    $<$<CONFIG:Debug>:${SANITIZE_FLAGS}>
)

# =============================================================================
# Test runner
# =============================================================================

add_executable(test_runner ${TEST_SRCS_C})

target_include_directories(test_runner PRIVATE ${INCLUDE_DIR} ${UNITY_DIR})

target_compile_options(test_runner PRIVATE
    ${PROJECT_BASE_FLAGS}
    ${PROJECT_WARNINGS}
    $<$<CONFIG:Debug>:${SANITIZE_FLAGS}>
)

target_compile_definitions(test_runner PRIVATE
    $<$<CONFIG:Debug>:DEBUG>
)

target_link_libraries(test_runner PRIVATE verum)

target_link_options(test_runner PRIVATE
    $<$<CONFIG:Debug>:${SANITIZE_FLAGS}>
)

# =============================================================================
# CTest
# =============================================================================

enable_testing()

add_test(
    NAME    unit_tests
    COMMAND test_runner
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

set_tests_properties(unit_tests PROPERTIES
    ENVIRONMENT "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1"
)

# =============================================================================
# run_tests — cmake --build build -t run_tests
# =============================================================================

add_custom_target(run_tests
    COMMAND ${CMAKE_COMMAND} -E echo
        "━━━ Running unit tests ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    COMMAND $<TARGET_FILE:test_runner>
    COMMAND ${CMAKE_COMMAND} -E echo
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    DEPENDS test_runner
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running unit tests"
    USES_TERMINAL
    VERBATIM
)

# =============================================================================
# compile_commands.json symlink in project root
# =============================================================================

add_custom_target(symlink_ccdb ALL
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        ${CMAKE_BINARY_DIR}/compile_commands.json
        ${CMAKE_SOURCE_DIR}/compile_commands.json
    COMMENT "Symlinking compile_commands.json → project root"
    VERBATIM
)

# =============================================================================
# Uncrustify — cmake --build build -t uncrustify
# =============================================================================

find_program(UNCRUSTIFY_EXE NAMES uncrustify)

if(UNCRUSTIFY_EXE)
    add_custom_target(uncrustify
        COMMAND ${UNCRUSTIFY_EXE}
            -c ${CMAKE_SOURCE_DIR}/.uncrustify.cfg
            --replace --no-backup
            ${SOURCES_C} ${HEADERS} ${TEST_SRCS_C}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Formatting sources with uncrustify"
        VERBATIM
    )
else()
    add_custom_target(uncrustify
        COMMAND ${CMAKE_COMMAND} -E echo "uncrustify not found"
        VERBATIM
    )
    message(WARNING "uncrustify not found; target is a no-op")
endif()

# =============================================================================
# Cppcheck — cmake --build build -t cppcheck
# =============================================================================

find_program(CPPCHECK_EXE NAMES cppcheck)

if(CPPCHECK_EXE)
    add_custom_target(cppcheck
        COMMAND ${CPPCHECK_EXE}
            --force -q
            --check-level=exhaustive
            --enable=all
            -I ${INCLUDE_DIR}
            --checkers-report=${CMAKE_SOURCE_DIR}/cppcheck_report.xml
            ${SOURCES_C} ${HEADERS}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Running cppcheck"
        VERBATIM
    )
else()
    add_custom_target(cppcheck
        COMMAND ${CMAKE_COMMAND} -E echo "cppcheck not found"
        VERBATIM
    )
    message(WARNING "cppcheck not found; target is a no-op")
endif()

# =============================================================================
# Configure summary
# =============================================================================

message(STATUS "──────────────────────────────────────────")
message(STATUS "  Project  : ${PROJECT_NAME} ${PROJECT_VERSION}")
message(STATUS "  Compiler : ${CMAKE_C_COMPILER}")
message(STATUS "  Standard : C${CMAKE_C_STANDARD}")
message(STATUS "  Build    : ${CMAKE_BUILD_TYPE}")
message(STATUS "  DebugInfo: ${DEBUG_INFO_FLAG}")
message(STATUS "  Targets  : verum  test_runner  run_tests")
message(STATUS "             uncrustify  cppcheck")
message(STATUS "──────────────────────────────────────────")