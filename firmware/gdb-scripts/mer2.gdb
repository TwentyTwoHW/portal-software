# Unlock flash
set *0x40022008 = 0x45670123
set *0x40022008 = 0xCDEF89AB

# Unlock opt bytes
# set *0x4002200C = 0x08192A3B
# set *0x4002200C = 0x4C5D6E7F

x/xw 0x40022014

# mass-erase bank2
set *0x40022014 = 0x18000

# monitor reset halt
