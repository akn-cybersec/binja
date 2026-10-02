# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
DEBUG_FLAGS = -g -O0 -DDEBUG
LDFLAGS = -lcapstone

# Versioning >_<
VERSION := $(shell cat VERSION 2>/dev/null | tr -d '[:space:]' || echo 0.0.0)
GIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

CXXFLAGS += -DBINJA_VERSION=\"$(VERSION)\"
CXXFLAGS += -DBINJA_BUILD_INFO=\"$(GIT_HASH)-$(BUILD_DATE)\"

# Target and sources
TARGET = binja

SOURCES = main.cpp elf_parser.cpp disassembler.cpp patcher.cpp rop_finder.cpp
OBJECTS = $(SOURCES:.cpp=.o)
HEADERS = elf_parser.h disassembler.h patcher.h rop_finder.h

# Colors
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[0;33m
BLUE = \033[0;34m
RESET = \033[0m

.PHONY: all clean debug help

# Default target
all: $(TARGET)

# Link
$(TARGET): $(OBJECTS)
	@echo "$(GREEN)[LD]$(RESET) Linking $@"
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Compile
%.o: %.cpp $(HEADERS)
	@echo "$(BLUE)[CXX]$(RESET) Compiling $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Debug build
debug: CXXFLAGS += $(DEBUG_FLAGS)
debug: clean $(TARGET)

# Clean
clean:
	@echo "$(YELLOW)[CLEAN]$(RESET) Removing object files and binary"
	rm -f $(OBJECTS) $(TARGET)

# Help
help:
	@echo "$(BLUE)╔════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(BLUE)║$(RESET)          $(GREEN)binja Build System$(RESET)                    $(BLUE)║$(RESET)"
	@echo "$(BLUE)╚════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@echo "$(YELLOW)Targets:$(RESET)"
	@echo "  $(GREEN)all$(RESET)          - Build binja (default)"
	@echo "  $(GREEN)debug$(RESET)        - Build with debug symbols"
	@echo "  $(GREEN)clean$(RESET)        - Remove build artifacts"
	@echo "  $(GREEN)help$(RESET)         - Show this help"
	@echo ""
	@echo "$(YELLOW)Examples:$(RESET)"
	@echo "  $(BLUE)make$(RESET)                 # Build binja"
	@echo "  $(BLUE)make debug$(RESET)          # Build debug version"
	@echo "  $(BLUE)make clean$(RESET)          # Clean build artifacts"
	@echo "  $(BLUE)sudo ./install.sh$(RESET)   # Install binja"
	@echo ""
