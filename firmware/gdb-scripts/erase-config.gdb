# Unlock flash
set *0x40022008 = 0x45670123
set *0x40022008 = 0xCDEF89AB

# Start the flashing
set *0x40022014 = 0x000107FA
set *0x40022014 = 0x00010FFA

monitor reset halt
c
