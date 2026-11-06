cmake_minimum_required(VERSION 3.25)

find_package(Python3 COMPONENTS Interpreter REQUIRED)
find_program(QEMU_ARM_EXE NAMES qemu-system-arm)
find_program(QEMU_RISCV32_EXE NAMES qemu-system-riscv32)

if(QEMU_ARM_EXE AND QEMU_RISCV32_EXE)
    add_custom_target(qemu_benchmark
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/benchmark/run_bench.py
        DEPENDS release_arm release_riscv
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Running bare-metal QEMU benchmark matrix across ARMv7E-M and RISC-V 32"
        USES_TERMINAL
        VERBATIM
    )
else()
    message(WARNING "qemu-system-arm or qemu-system-riscv32 not found; 'qemu_benchmark' target will not be available")
endif()
