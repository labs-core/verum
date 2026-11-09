ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 8M
}

SECTIONS
{
    .text :
    {
        KEEP(*(.text.start))
        *(.text*)
    } > RAM

    .rodata :
    {
        *(.rodata*)
        *(.srodata*)
    } > RAM

    .data :
    {
        *(.data*)
        *(.sdata*)
    } > RAM

    .bss :
    {
        *(.bss*)
        *(.sbss*)
        *(COMMON)
    } > RAM

    . = ALIGN(16);
    __stack_bottom = .;
    . = . + 0x4000;
    __stack_top = .;
}
