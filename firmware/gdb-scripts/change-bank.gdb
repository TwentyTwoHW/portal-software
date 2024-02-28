monitor reset halt

# Unlock flash
set *0x40022008 = 0x45670123
set *0x40022008 = 0xCDEF89AB

# Unlock opt bytes
set *0x4002200C = 0x08192A3B
set *0x4002200C = 0x4C5D6E7F

# Write FLASH_OPTR to default
set *0x40022020 = 0xFFEFF8AA

# Start the flashing
set *0x40022014 = 0x00020000

# Set OBL_LAUNCH which will cause a restart
set *0x40022014 = 0x08000000

monitor reset halt