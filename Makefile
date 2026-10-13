CC := gcc
CPPFLAGS := -Iinclude
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic
LDFLAGS :=
LDLIBS :=

SRC_DIR := src
BUILD_DIR := build
TARGET := meu_cliente

SOURCES := \
    $(SRC_DIR)/main.c \
    $(SRC_DIR)/dns_protocol.c \
    $(SRC_DIR)/udp_client.c \
    $(SRC_DIR)/dns_parser.c

OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))
DEPS := $(OBJECTS:.o=.d)

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(DEPS)

run: $(TARGET)
	./$(TARGET) $(ARGS)

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
