cmake_minimum_required(VERSION 3.25)

set(CMAKE_C_COMPILER clang)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(VERUM
    VERSION     0.1.0
    LANGUAGES   C
    DESCRIPTION "Cryptographic primitives suite for mission-critical and safety-critical software"
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)  


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

file(GLOB RUNNER_SRCS CONFIGURE_DEPENDS ${TEST_DIR}/runner.c)
file(GLOB UNITY_SRCS  CONFIGURE_DEPENDS ${UNITY_DIR}/*.c)
file(GLOB SUITE_ASCON CONFIGURE_DEPENDS ${SUITE_DIR}/ascon/*.c)

set(TEST_SRCS_C ${RUNNER_SRCS} ${UNITY_SRCS} ${SUITE_ASCON})
set(TEST_INCLUDE_DIRS ${INCLUDE_DIR} ${UNITY_DIR} ${SUITE_DIR}/ascon)

file(GLOB_RECURSE BENCH_SRCS CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/benchmark/*.c ${CMAKE_SOURCE_DIR}/benchmark/*.h)

# -----------------------------------------------------------------------------
# Unified Compilation Flags and Matrix Configurations (release/flags.cmake)
# -----------------------------------------------------------------------------
include(${CMAKE_SOURCE_DIR}/release/flags.cmake)
set(SANITIZE_FLAGS -fsanitize=address,undefined)

enable_testing()

if(WIN32)
    set(RUN_TESTS_ASAN_OPTIONS "abort_on_error=1")
else()
    set(RUN_TESTS_ASAN_OPTIONS "detect_leaks=1:abort_on_error=1")
endif()

find_package(Python3 COMPONENTS Interpreter REQUIRED)

# -----------------------------------------------------------------------------
# Release Artifact Generation (x86_64, ARM Cortex-M4, RISC-V 32 RV32IMAC)
# -----------------------------------------------------------------------------
set(RELEASE_DIR ${CMAKE_SOURCE_DIR}/release)

add_custom_target(release_x86_64
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/release/run_release.py --arch x86_64 --out-dir ${RELEASE_DIR}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Building stripped release static archives for x86_64 host"
    VERBATIM
)

add_custom_target(release_arm
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/release/run_release.py --arch arm --out-dir ${RELEASE_DIR}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Building stripped release static archives for ARM Cortex-M4"
    VERBATIM
)

add_custom_target(release_riscv
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/release/run_release.py --arch riscv --out-dir ${RELEASE_DIR}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Building stripped release static archives for RISC-V 32 RV32IMAC"
    VERBATIM
)

add_custom_target(release
    DEPENDS release_x86_64 release_arm release_riscv
    COMMENT "Building complete stripped release libraries for x86_64, ARM, and RISC-V"
)

add_library(verum OBJECT ${SOURCES_C})
target_include_directories(verum PUBLIC ${INCLUDE_DIR})
target_compile_options(verum PRIVATE
    ${PROJECT_BASE_FLAGS} ${PROJECT_WARNINGS}
    $<$<CONFIG:Debug>:${SANITIZE_FLAGS}>
)
target_compile_definitions(verum PRIVATE $<$<CONFIG:Debug>:DEBUG>)
target_link_options(verum INTERFACE $<$<CONFIG:Debug>:${SANITIZE_FLAGS}>)

add_executable(test_runner ${TEST_SRCS_C})
target_include_directories(test_runner PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_options(test_runner PRIVATE
    ${PROJECT_BASE_FLAGS} ${PROJECT_WARNINGS}
)
target_link_libraries(test_runner PRIVATE ${RELEASE_DIR}/verum/ad_direct_unrolled/x86_64/libverum.a)
add_dependencies(test_runner release_x86_64)

# -----------------------------------------------------------------------------
# Ascon Configuration Permutation Matrix (12 Configurations from flags.cmake)
# -----------------------------------------------------------------------------
set(ALL_MATRIX_TEST_RUNNERS "")

foreach(CFG IN LISTS MATRIX_CONFIG_NAMES)
    set(CFG_RUNNER test_runner_${CFG})

    add_executable(${CFG_RUNNER} ${TEST_SRCS_C})
    target_include_directories(${CFG_RUNNER} PRIVATE ${TEST_INCLUDE_DIRS})
    target_compile_options(${CFG_RUNNER} PRIVATE
        ${PROJECT_BASE_FLAGS} ${PROJECT_WARNINGS}
    )
    target_compile_definitions(${CFG_RUNNER} PRIVATE
        ${DEFS_${CFG}}
        $<$<CONFIG:Debug>:DEBUG>
    )
    target_link_libraries(${CFG_RUNNER} PRIVATE ${RELEASE_DIR}/verum/${CFG}/x86_64/libverum.a)
    add_dependencies(${CFG_RUNNER} release_x86_64)

    add_test(NAME ascon_${CFG} COMMAND ${CFG_RUNNER})
    set_tests_properties(ascon_${CFG} PROPERTIES
        ENVIRONMENT "ASAN_OPTIONS=${RUN_TESTS_ASAN_OPTIONS}"
    )

    list(APPEND ALL_MATRIX_TEST_RUNNERS ${CFG_RUNNER})
endforeach()

add_custom_target(run_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS test_runner ${ALL_MATRIX_TEST_RUNNERS}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running CTest matrix across all configurations"
    USES_TERMINAL
    VERBATIM
)

add_subdirectory(benchmark)

find_program(UNCRUSTIFY_EXE NAMES uncrustify)
if(UNCRUSTIFY_EXE)
    add_custom_target(uncrustify
        COMMAND ${UNCRUSTIFY_EXE}
            -c ${CMAKE_SOURCE_DIR}/.uncrustify.cfg
            --replace --no-backup
            ${SOURCES_C} ${HEADERS} ${TEST_SRCS_C} ${BENCH_SRCS}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Formatting sources with uncrustify"
        VERBATIM
    )
else()
    message(WARNING "uncrustify not found; 'uncrustify' target will not be available")
endif()

find_program(CPPCHECK_EXE NAMES cppcheck)
if(CPPCHECK_EXE)
    add_custom_target(cppcheck
        COMMAND ${CPPCHECK_EXE}
            --language=c --std=c11
            --force -q
            --check-level=exhaustive
            --enable=all
            --inconclusive
            --addon=misra.py
            --inline-suppr
            --error-exitcode=1
            --template=gcc
            --suppress=checkersReport
            --suppress=misra-c2012-17.8
            --suppress=misra-c2012-18.4
            --suppress=misra-c2012-20.5
            --checkers-report=cppcheck.log
            "-D__builtin_assume_aligned(p,a)=(p)"
            -I ${INCLUDE_DIR}
            ${SOURCES_C}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Running cppcheck"
        USES_TERMINAL
        VERBATIM
    )
else()
    message(WARNING "cppcheck not found; 'cppcheck' target will not be available")
endif()

find_program(DOXYGEN_EXE NAMES doxygen)
if(DOXYGEN_EXE)
    add_custom_target(docs
        COMMAND ${DOXYGEN_EXE} ${CMAKE_SOURCE_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Generating documentation with Doxygen"
        VERBATIM
    )
else()
    message(WARNING "doxygen not found; 'docs' target will not be available")
endif()

file(RELATIVE_PATH BUILD_REL ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR})
if(BUILD_REL STREQUAL "")
    set(BUILD_REL ".")
endif()

message(STATUS "${PROJECT_NAME} ${PROJECT_VERSION} configured (${CMAKE_C_COMPILER}, C${CMAKE_C_STANDARD})")
message(STATUS "")
message(STATUS "Build:")
message(STATUS "  cmake --build ${BUILD_REL}                  # build everything")
message(STATUS "  cmake --build ${BUILD_REL} --target verum   # build the default library only")
message(STATUS "  cmake --build ${BUILD_REL} --target release        # build stripped release libraries for all architectures")
message(STATUS "  cmake --build ${BUILD_REL} --target release_x86_64 # build release libraries for x86_64 host")
message(STATUS "  cmake --build ${BUILD_REL} --target release_arm    # build release libraries for ARM Cortex-M4")
message(STATUS "  cmake --build ${BUILD_REL} --target release_riscv  # build release libraries for RISC-V 32")
message(STATUS "")
message(STATUS "Test:")
message(STATUS "  cmake --build ${BUILD_REL} --target run_tests       # build + run all 12 configuration tests (CTest)")
message(STATUS "  ctest --test-dir ${BUILD_REL} --output-on-failure   # run CTest suite directly")
message(STATUS "")
message(STATUS "Benchmark:")
message(STATUS "  cmake --build ${BUILD_REL} --target qemu_benchmark  # run QEMU bare-metal benchmark matrix")
message(STATUS "")
message(STATUS "Other:")
if(UNCRUSTIFY_EXE)
    message(STATUS "  cmake --build ${BUILD_REL} --target uncrustify      # format sources in place")
endif()
if(CPPCHECK_EXE)
    message(STATUS "  cmake --build ${BUILD_REL} --target cppcheck        # run static analysis")
endif()
if(DOXYGEN_EXE)
    message(STATUS "  cmake --build ${BUILD_REL} --target docs            # generate Doxygen documentation")
endif()
