# Toolchain
CC = arm-none-eabi-gcc
OBJCOPY = arm-none-eabi-objcopy
OBJDUMP = arm-none-eabi-objdump
SIZE = arm-none-eabi-size

USECTOOL = usectool

# Build configuration
BUILD_DIR = build
TARGET = $(BUILD_DIR)/firmware.elf

# Cortex-M3 flags
ARCH_FLAGS = -mcpu=cortex-m4 -mthumb -mfloat-abi=soft
OPT_FLAGS = -Os -ffunction-sections -fdata-sections
WARN_FLAGS = -Wall -Wextra

CFLAGS = $(ARCH_FLAGS) $(OPT_FLAGS) $(WARN_FLAGS) $(INCLUDES)
LDFLAGS = $(ARCH_FLAGS) -Wl,--gc-sections -Wl,--print-memory-usage
LDFLAGS += -Tlinker.ld

# Source files
LOCAL_SRCS = $(wildcard *.c)

# Object files
OBJ = $(addprefix $(BUILD_DIR)/, $(LOCAL_SRCS:.c=.o))

# Default target
all: $(TARGET)

# Create build directory structure
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Compilation rules
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link executable
$(TARGET): $(OBJ) linker.ld
	$(CC) $(LDFLAGS) $(OBJ) -o $@
	@echo "Build complete:"
	@$(SIZE) $@

# Create binary for flashing
$(BUILD_DIR)/firmware.bin: $(TARGET)
	$(OBJCOPY) -O binary $< $@

$(BUILD_DIR)/signed_firmware.bin: $(BUILD_DIR)/firmware.bin
	@echo "Generating test image"
	$(USECTOOL) genimage $(BUILD_DIR)/firmware.bin -k ../../keys/key0_private.pem -s ../../keys/signed_pkey.bin -o $@

flash: $(BUILD_DIR)/signed_firmware.bin
	@echo "Flashing firmware..."
	st-flash --connect-under-reset write $(BUILD_DIR)/signed_firmware.bin 0x08020000

signed: $(BUILD_DIR)/signed_firmware.bin

# Analysis targets
size: $(TARGET)
	@$(SIZE) $<

# Cleanup
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all signed clean size