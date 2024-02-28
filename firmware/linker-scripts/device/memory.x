/* Linker script for the STM32L476 */
MEMORY
{
    FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 510K
    /* FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 768K */
    DATA (r) : ORIGIN = 0x0807F800, LENGTH = 2K
    /* Use the largest section of memory for the HEAP */
    HEAP (rw) : ORIGIN = 0x20000000, LENGTH = 96K
    /* And place the stack in SRAM2 which should be more than enough */
    RAM (rw) : ORIGIN = 0x10000000, LENGTH = 32K
}

SECTIONS
{
    .heap (NOLOAD) : ALIGN(4)
    {
        *(.heap .heap.*);
    } > HEAP
}
