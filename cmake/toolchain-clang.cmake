# =============================================================================
# cmake/toolchain-clang.cmake
#
# Usage:
#   cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-clang.cmake
#   cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-clang.cmake \
#                  -DCMAKE_BUILD_TYPE=Debug
# =============================================================================

set(CMAKE_C_COMPILER   clang  CACHE STRING "C compiler")

# If you ever add C++ sources, clang++ is picked up automatically.
# Uncomment if you want to pin it explicitly:
# set(CMAKE_CXX_COMPILER clang++ CACHE STRING "C++ compiler")

# Use LLVM's archiver / ranlib so LTO and thin-archives work out of the box
# when you eventually enable them.  Falls back gracefully if not installed.
find_program(LLVM_AR      NAMES llvm-ar)
find_program(LLVM_RANLIB  NAMES llvm-ranlib)
find_program(LLVM_NM      NAMES llvm-nm)

if(LLVM_AR)
    set(CMAKE_AR      "${LLVM_AR}"     CACHE STRING "Archiver")
endif()
if(LLVM_RANLIB)
    set(CMAKE_RANLIB  "${LLVM_RANLIB}" CACHE STRING "Ranlib")
endif()
if(LLVM_NM)
    set(CMAKE_NM      "${LLVM_NM}"     CACHE STRING "nm")
endif()
