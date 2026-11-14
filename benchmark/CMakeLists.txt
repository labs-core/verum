cmake_minimum_required(VERSION 3.25)

find_package(Python3 COMPONENTS Interpreter REQUIRED)
find_program(QEMU_ARM_EXE NAMES qemu-system-arm)
find_program(QEMU_RISCV32_EXE NAMES qemu-system-riscv32)

if(WIN32)
    find_program(WSL_EXECUTABLE NAMES wsl.exe)
    set(TRICORE_QEMU_AVAILABLE ${WSL_EXECUTABLE})
else()
    find_program(QEMU_TRICORE_EXE NAMES qemu-system-tricore)
    set(TRICORE_QEMU_AVAILABLE ${QEMU_TRICORE_EXE})
endif()

if(QEMU_ARM_EXE AND QEMU_RISCV32_EXE AND TRICORE_QEMU_AVAILABLE)
    add_custom_target(qemu_benchmark
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/benchmark/run_bench.py --arch all
        DEPENDS release_arm release_riscv release_tricore
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Running bare-metal QEMU benchmark matrix across ARMv7E-M, RISC-V 32, and TriCore TC37x"
        USES_TERMINAL
        VERBATIM
    )
else()
    message(WARNING "ARM QEMU, RISC-V QEMU, or TriCore QEMU/WSL not found; 'qemu_benchmark' target will not be available")
endif()
