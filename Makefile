# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
GIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
CXXFLAGS += -DBINJA_VERSION=\"$(GIT_HASH)\" -DBINJA_BUILD_INFO=\"built-$(BUILD_DATE)\"
DEBUG_FLAGS = -g -O0 -DDEBUG
LDFLAGS = -lcapstone

# Target and sources
TARGET = binja
SOURCES = main.cpp elf_parser.cpp disassembler.cpp patcher.cpp rop_finder.cpp
OBJECTS = $(SOURCES:.cpp=.o)
HEADERS = elf_parser.h disassembler.h patcher.h rop_finder.h

# Installation paths - changed to /usr/bin by default
PREFIX ?= /usr
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man/man1
DOCDIR = $(PREFIX)/share/doc/binja

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[0;33m
BLUE = \033[0;34m
RESET = \033[0m

.PHONY: all clean debug help install uninstall distclean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@echo "$(GREEN)[LD]$(RESET) Linking $@"
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp $(HEADERS)
	@echo "$(BLUE)[CXX]$(RESET) Compiling $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

debug: CXXFLAGS += $(DEBUG_FLAGS)
debug: clean $(TARGET)

# Install to system - now defaults to /usr/bin
install: $(TARGET)
	@echo "$(GREEN)[INSTALL]$(RESET) Installing binja to $(BINDIR)"
	@mkdir -p $(BINDIR)
	@cp $(TARGET) $(BINDIR)/
	@chmod 755 $(BINDIR)/$(TARGET)
	@echo "$(GREEN)[OK]$(RESET) Installed to $(BINDIR)/$(TARGET)"
	
	@if [ -f binja.1 ]; then \
		echo "$(GREEN)[INSTALL]$(RESET) Installing man page"; \
		mkdir -p $(MANDIR); \
		cp binja.1 $(MANDIR)/; \
		chmod 644 $(MANDIR)/binja.1; \
		echo "$(GREEN)[OK]$(RESET) Man page installed"; \
	fi
	
	@if [ -f README.md ]; then \
		echo "$(GREEN)[INSTALL]$(RESET) Installing documentation"; \
		mkdir -p $(DOCDIR); \
		cp README.md $(DOCDIR)/; \
		echo "$(GREEN)[OK]$(RESET) Documentation installed"; \
	fi
	
	@echo ""
	@echo "$(GREEN)✓ binja installed successfully!$(RESET)"
	@echo "  Run with: $(YELLOW)binja <binary>$(RESET)"
	@echo ""

# Uninstall from system
uninstall:
	@echo "$(RED)[REMOVE]$(RESET) Uninstalling binja"
	@rm -f $(BINDIR)/$(TARGET)
	@rm -f $(MANDIR)/binja.1
	@rm -rf $(DOCDIR)
	@echo "$(GREEN)[OK]$(RESET) Uninstalled successfully"

# Clean build artifacts
clean:
	@echo "$(YELLOW)[CLEAN]$(RESET) Removing object files and binary"
	rm -f $(OBJECTS) $(TARGET)

# Deep clean including install artifacts
distclean: clean uninstall
	@echo "$(YELLOW)[DISTCLEAN]$(RESET) Removed all build and install artifacts"

# Help
help:
	@echo "$(BLUE)╔════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(BLUE)║$(RESET)          $(GREEN)binja Build System$(RESET)                    $(BLUE)║$(RESET)"
	@echo "$(BLUE)╚════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@echo "$(YELLOW)Targets:$(RESET)"
	@echo "  $(GREEN)all$(RESET)          - Build binja (default)"
	@echo "  $(GREEN)debug$(RESET)        - Build with debug symbols and optimizations off"
	@echo "  $(GREEN)install$(RESET)      - Install binja to $(BINDIR) (requires sudo)"
	@echo "  $(GREEN)uninstall$(RESET)    - Remove binja from system"
	@echo "  $(GREEN)clean$(RESET)        - Remove object files and binary"
	@echo "  $(GREEN)distclean$(RESET)    - Clean + uninstall everything"
	@echo "  $(GREEN)help$(RESET)         - Show this help"
	@echo ""
	@echo "$(YELLOW)Installation paths:$(RESET)"
	@echo "  Binary:    $(BINDIR)/$(TARGET)"
	@echo "  Man page:  $(MANDIR)/binja.1 (if exists)"
	@echo "  Docs:      $(DOCDIR)/"
	@echo ""
	@echo "$(YELLOW)Examples:$(RESET)"
	@echo "  $(BLUE)make$(RESET)                         # Build binja"
	@echo "  $(BLUE)sudo make install$(RESET)            # Install to $(BINDIR)"
	@echo "  $(BLUE)make PREFIX=/usr/local install$(RESET) # Install to /usr/local"
	@echo "  $(BLUE)make debug$(RESET)                   # Build debug version"
	@echo ""

# Dependency tracking
main.o: main.cpp elf_parser.h disassembler.h patcher.h rop_finder.h
elf_parser.o: elf_parser.cpp elf_parser.h
disassembler.o: disassembler.cpp disassembler.h elf_parser.h
rop_finder.o: rop_finder.cpp rop_finder.h elf_parser.h disassembler.h
patcher.o: patcher.cpp patcher.h elf_parser.h