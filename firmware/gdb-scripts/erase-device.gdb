# Unlock flash
set *0x40022008 = 0x45670123
set *0x40022008 = 0xCDEF89AB

# Start the flashing
set *0x40022014 = 0x00018004

# monitor reset halt
