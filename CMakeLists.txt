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
    -ftrapping-math
    -frounding-math
    -fno-common
    -fno-exceptions
    -fno-unwind-tables
    -fno-asynchronous-unwind-tables
    -fdiagnostics-show-option
    -ferror-limit=0
    -fmacro-backtrace-limit=0
)

set(PROJECT_BASE_FLAGS -O0 $<$<CONFIG:Debug>:-g3>)
set(SANITIZE_FLAGS -fsanitize=address,undefined)

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
    $<$<CONFIG:Debug>:${SANITIZE_FLAGS}>
)
target_compile_definitions(test_runner PRIVATE $<$<CONFIG:Debug>:DEBUG>)
target_link_libraries(test_runner PRIVATE verum)
target_link_options(test_runner PRIVATE $<$<CONFIG:Debug>:${SANITIZE_FLAGS}>)

if(WIN32)
    set(RUN_TESTS_ASAN_OPTIONS "abort_on_error=1")
else()
    set(RUN_TESTS_ASAN_OPTIONS "detect_leaks=1:abort_on_error=1")
endif()

add_custom_target(run_tests
    COMMAND ${CMAKE_COMMAND} -E env ASAN_OPTIONS=${RUN_TESTS_ASAN_OPTIONS}
        $<TARGET_FILE:test_runner>
    DEPENDS test_runner
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running unit tests"
    USES_TERMINAL
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
            -D"__builtin_assume_aligned(p,a)=(p)"
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
message(STATUS "  cmake --build ${BUILD_REL} --target verum   # build the library only")
message(STATUS "")
message(STATUS "Test:")
message(STATUS "  cmake --build ${BUILD_REL} --target run_tests       # build + run test_runner")
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