# Makefile for librampart - Cross-platform LD_PRELOAD library

# Detect platform
UNAME_S := $(shell uname -s)

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -Werror -pedantic -std=c99 -fPIC
LDFLAGS := -lcurl -lpthread

# Platform-specific settings
ifeq ($(UNAME_S),Linux)
    TARGET := librampart.so
    SHARED_FLAG := -shared
    LDFLAGS += -ldl
endif

ifeq ($(UNAME_S),Darwin)
    TARGET := librampart.dylib
    SHARED_FLAG := -dynamiclib
    CFLAGS += -Wno-deprecated-declarations
endif

# Source file
SRC := librampart.c
TEST_SRC := librampart_test.c
TEST_TARGET := librampart_test

# Default target
all: $(TARGET)

# Build the shared library
$(TARGET): $(SRC)
	$(CC) $(SHARED_FLAG) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "Built $(TARGET) for $(UNAME_S)"

# Debug build with symbols
debug: CFLAGS += -g -O0 -DDEBUG
debug: $(TARGET)

# AddressSanitizer build
asan: CFLAGS += -fsanitize=address -g -O1
asan: LDFLAGS += -fsanitize=address
asan: $(TARGET)

# Test target - helper/parser/unit coverage plus a shared-library build.
test: $(TARGET)
	$(CC) $(CFLAGS) -o $(TEST_TARGET) $(TEST_SRC) $(LDFLAGS)
	./$(TEST_TARGET)

# Install to user's rampart directory
install: $(TARGET)
	@mkdir -p ~/.rampart/lib
	@cp $(TARGET) ~/.rampart/lib/
	@echo "Installed $(TARGET) to ~/.rampart/lib/"

# Clean build artifacts
clean:
	@rm -f librampart.so librampart.dylib $(TEST_TARGET)
	@echo "Cleaned build artifacts"

# Display help
help:
	@echo "Available targets:"
	@echo "  all      - Build the shared library (default)"
	@echo "  debug    - Build with debug symbols"
	@echo "  asan     - Build with AddressSanitizer"
	@echo "  test     - Run basic smoke tests"
	@echo "  install  - Install to ~/.rampart/lib/"
	@echo "  clean    - Remove build artifacts"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Platform: $(UNAME_S)"
	@echo "Target:   $(TARGET)"

.PHONY: all debug asan test install clean help
