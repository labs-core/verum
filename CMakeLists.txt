cmake_minimum_required(VERSION 3.25)

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

set(SOURCE_DIR  ${CMAKE_SOURCE_DIR}/source)
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(TEST_DIR    ${CMAKE_SOURCE_DIR}/test)
set(UNITY_DIR   ${TEST_DIR}/unity)
set(SUITE_DIR   ${TEST_DIR}/suite)

file(GLOB_RECURSE SOURCES_C CONFIGURE_DEPENDS ${SOURCE_DIR}/*.c)
file(GLOB_RECURSE HEADERS   CONFIGURE_DEPENDS ${INCLUDE_DIR}/*.h)

if(NOT SOURCES_C)
    message(FATAL_ERROR "No .c files found under ${SOURCE_DIR}")
endif()

file(GLOB UNITY_SRCS    CONFIGURE_DEPENDS ${UNITY_DIR}/*.c)
file(GLOB RUNNER_SRCS   CONFIGURE_DEPENDS ${TEST_DIR}/runner.c)

file(GLOB SUITE_ASCON   CONFIGURE_DEPENDS ${SUITE_DIR}/ascon/*.c)

set(TEST_SRCS_C
    ${RUNNER_SRCS}
    ${UNITY_SRCS}
    ${SUITE_ASCON}
)

set(TEST_INCLUDE_DIRS
    ${INCLUDE_DIR}
    ${UNITY_DIR}
    ${SUITE_DIR}/ascon
)

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

set(DEBUG_INFO_FLAG $<$<CONFIG:Debug>:-g3>)
set(PROJECT_BASE_FLAGS  -O0 ${DEBUG_INFO_FLAG})
set(SANITIZE_FLAGS      -fsanitize=address,undefined)

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

target_link_options(verum INTERFACE
    $<$<CONFIG:Debug>:${SANITIZE_FLAGS}>
)

add_executable(test_runner ${TEST_SRCS_C})

target_include_directories(test_runner PRIVATE ${TEST_INCLUDE_DIRS})

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

enable_testing()

add_test(
    NAME    unit_tests
    COMMAND test_runner
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

set_tests_properties(unit_tests PROPERTIES
    ENVIRONMENT "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1"
)

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

add_custom_target(symlink_ccdb ALL
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        ${CMAKE_BINARY_DIR}/compile_commands.json
        ${CMAKE_SOURCE_DIR}/compile_commands.json
    COMMENT "Symlinking compile_commands.json → project root"
    VERBATIM
)

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

find_program(CPPCHECK_EXE NAMES cppcheck)

if(CPPCHECK_EXE)
    add_custom_target(cppcheck
        COMMAND ${CPPCHECK_EXE}
            --force -q
            --check-level=exhaustive
            --enable=all
            --addon=misra.py
            -I ${INCLUDE_DIR}
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

find_program(LLVM_STRIP_EXE   NAMES llvm-strip)
find_program(LLVM_OBJCOPY_EXE NAMES llvm-objcopy)

if(LLVM_STRIP_EXE)
    set(STRIP_TOOL "${LLVM_STRIP_EXE}")
    set(STRIP_ARGS --strip-debug)
elseif(LLVM_OBJCOPY_EXE)
    set(STRIP_TOOL "${LLVM_OBJCOPY_EXE}")
    set(STRIP_ARGS --strip-debug)
    message(STATUS "llvm-strip not found; using llvm-objcopy --strip-debug")
else()
    set(STRIP_TOOL "${CMAKE_COMMAND}")
    set(STRIP_ARGS -E echo "WARNING: no strip tool found; skipping strip of")
    message(WARNING "Neither llvm-strip nor llvm-objcopy found — libraries will NOT be stripped")
endif()

set(BAREMETAL_CFLAGS
    --std=c11
    -ffreestanding
    -fno-builtin
    -nostdlib
    -fno-stack-protector
    -O2
    ${PROJECT_WARNINGS}
    -Wno-unknown-warning-option
)

set(BAREMETAL_TRIPLES
    armv6m-none-eabi
    armv7m-none-eabi
    armv7em-none-eabi
    armv7em-none-eabihf
    armv8m.base-none-eabi
    armv8m.main-none-eabi
    armv8m.main-none-eabihf
    armv8.1m.main-none-eabi
    armv8.1m.main-none-eabihf
    armv7a-none-eabi
    armv7r-none-eabi
    armv8a-none-eabi
    aarch64-none-elf
    riscv32-none-elf
    riscv64-none-elf
    mips-none-elf
    mipsel-none-elf
    mips64-none-elf
    mips64el-none-elf
    powerpc-none-eabi
    powerpc64-unknown-none-elf
    powerpc64le-unknown-none-elf
    i686-unknown-none-elf
    x86_64-unknown-none-elf
    wasm32-unknown-unknown
    wasm64-unknown-unknown
)

set(ALL_BAREMETAL_LIBS)

foreach(TRIPLE IN LISTS BAREMETAL_TRIPLES)

    string(REPLACE "-" "_" SAFE "${TRIPLE}")
    string(REPLACE "." "_" SAFE "${SAFE}")

    set(OUT_DIR "${CMAKE_BINARY_DIR}/baremetal/${TRIPLE}")
    set(TRIPLE_OBJS)

    foreach(SRC IN LISTS SOURCES_C)
        file(RELATIVE_PATH REL "${SOURCE_DIR}" "${SRC}")
        string(REPLACE "/"  "__" FLAT "${REL}")
        string(REPLACE "\\" "__" FLAT "${FLAT}")
        string(REPLACE ".c" ""   FLAT "${FLAT}")

        set(OBJ "${OUT_DIR}/${FLAT}.o")

        add_custom_command(
            OUTPUT  "${OBJ}"
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${OUT_DIR}"
            COMMAND clang
                    --target=${TRIPLE}
                    ${BAREMETAL_CFLAGS}
                    -I "${INCLUDE_DIR}"
                    -c "${SRC}"
                    -o "${OBJ}"
            DEPENDS "${SRC}" ${HEADERS}
            COMMENT "[baremetal/${TRIPLE}] compiling ${REL}"
            VERBATIM
        )

        list(APPEND TRIPLE_OBJS "${OBJ}")
    endforeach()

    set(LIB "${OUT_DIR}/libverum.a")

    add_custom_command(
        OUTPUT  "${LIB}"
        COMMAND "${CMAKE_AR}" rcs "${LIB}" ${TRIPLE_OBJS}
        COMMAND "${STRIP_TOOL}" ${STRIP_ARGS} "${LIB}"
        DEPENDS ${TRIPLE_OBJS}
        COMMENT "[baremetal/${TRIPLE}] archiving + stripping libverum.a"
        VERBATIM
    )

    add_custom_target(baremetal_${SAFE} DEPENDS "${LIB}")
    list(APPEND ALL_BAREMETAL_LIBS "${LIB}")

endforeach()

add_custom_target(baremetal
    DEPENDS ${ALL_BAREMETAL_LIBS}
    COMMENT "All bare-metal stripped libraries built under build/baremetal/"
)

list(LENGTH BAREMETAL_TRIPLES _N_TRIPLES)

message(STATUS "──────────────────────────────────────────")
message(STATUS "  Project  : ${PROJECT_NAME} ${PROJECT_VERSION}")
message(STATUS "  Compiler : ${CMAKE_C_COMPILER}")
message(STATUS "  Standard : C${CMAKE_C_STANDARD}")
message(STATUS "  Build    : ${CMAKE_BUILD_TYPE}")
message(STATUS "  DebugInfo: ${DEBUG_INFO_FLAG}")
message(STATUS "  Targets  : verum  test_runner  run_tests")
message(STATUS "             uncrustify  cppcheck")
message(STATUS "             baremetal  (${_N_TRIPLES} triples)")
message(STATUS "──────────────────────────────────────────")
