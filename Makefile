CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
DEBUG_FLAGS = -g -O0 -DDEBUG
LDFLAGS = -lcapstone

TARGET = binja
SOURCES = main.cpp elf_parser.cpp disassembler.cpp patcher.cpp
OBJECTS = $(SOURCES:.cpp=.o)
HEADERS = elf_parser.h disassembler.h patcher.h

.PHONY: all clean debug help

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

debug: CXXFLAGS += $(DEBUG_FLAGS)
debug: clean $(TARGET)

clean:
	rm -f $(OBJECTS) $(TARGET)

help:
	@echo "Available targets:"
	@echo "  all     - Build binja (default)"
	@echo "  debug   - Build with debug symbols"
	@echo "  clean   - Remove object files and binary"
	@echo "  help    - Show this help"

# Dependency tracking
main.o: main.cpp elf_parser.h disassembler.h patcher.h
elf_parser.o: elf_parser.cpp elf_parser.h
disassembler.o: disassembler.cpp disassembler.h elf_parser.h
patcher.o: patcher.cpp patcher.h elf_parser.h