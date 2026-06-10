#include "elf_parser.h"
#include "disassembler.h"
#include "patcher.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <chrono>
#include <ctime>
#include <signal.h>

// Global for signal handling
ElfParser* g_current_elf = nullptr;

// History file
const std::string HISTORY_FILE = ".binja_history";
std::vector<std::string> command_history;
size_t history_index = 0;

// Function prototypes
void print_usage(const char* progname);
void print_interactive_help();
void save_to_history(const std::string& cmd);
void load_history();
void add_to_history(const std::string& cmd);
std::string get_input();
void signal_handler(int sig);

// Command handlers (implementations)
void cmd_info(ElfParser& elf) {
    ElfInfo info = elf.get_info();
    
    std::cout << "Entry point: 0x" << std::hex << info.entry_point << std::dec << "\n";
    std::cout << "Architecture: " << info.architecture << "\n";
    std::cout << "Endianness: " << info.endianness << "\n";
    std::cout << "Sections: ";
    for (size_t i = 0; i < info.sections.size() && i < 10; i++) {
        std::cout << info.sections[i];
        if (i < info.sections.size() - 1 && i < 9) std::cout << ", ";
    }
    if (info.sections.size() > 10) std::cout << "...";
    std::cout << "\n";
    
    std::cout << "Protections: ";
    std::cout << "NX: " << (info.protections.nx ? "yes" : "no") << ", ";
    std::cout << "PIE: " << (info.protections.pie ? "yes" : "no") << ", ";
    std::cout << "Canary: " << (info.protections.canary ? "yes" : "no") << ", ";
    std::cout << "RELRO: " << info.protections.relro << "\n";
}

void cmd_functions(ElfParser& elf) {
    std::vector<Symbol> functions = elf.get_functions();
    
    if (functions.empty()) {
        std::cout << "No functions found (binary may be stripped)\n";
        return;
    }
    
    for (const auto& func : functions) {
        std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0') 
                  << func.address << std::dec << std::setfill(' ') 
                  << " " << func.name;
        if (func.size > 0) {
            std::cout << " (size: " << func.size << ")";
        }
        std::cout << "\n";
    }
}

void cmd_strings(ElfParser& elf, size_t min_len) {
    std::vector<std::string> strings = elf.get_strings(min_len);
    
    if (strings.empty()) {
        std::cout << "No strings found\n";
        return;
    }
    
    for (const auto& str : strings) {
        std::cout << str << "\n";
    }
}

bool is_hex_address(const std::string& str) {
    if (str.length() < 3) return false;
    if (str.substr(0, 2) != "0x") return false;
    for (size_t i = 2; i < str.length(); i++) {
        if (!std::isxdigit(str[i])) return false;
    }
    return true;
}

uint64_t parse_address(const std::string& str) {
    if (str.substr(0, 2) == "0x") {
        return std::stoull(str.substr(2), nullptr, 16);
    }
    return std::stoull(str, nullptr, 16);
}

void cmd_disas(ElfParser& elf, Disassembler& dis, const std::string& target) {
    // Initialize disassembler
    if (!dis.init(elf.is_64bit(), elf.is_little_endian())) {
        return;
    }
    
    if (is_hex_address(target)) {
        uint64_t addr = parse_address(target);
        dis.disassemble_function(addr, elf);
    } else {
        dis.disassemble_function(target, elf);
    }
}

void cmd_xrefs(ElfParser& elf, Disassembler& dis, const std::string& target) {
    if (!is_hex_address(target)) {
        std::cerr << "Error: Address must be in hex format (e.g., 0x401234)\n";
        return;
    }
    
    uint64_t addr = parse_address(target);
    
    // Initialize disassembler
    if (!dis.init(elf.is_64bit(), elf.is_little_endian())) {
        return;
    }
    
    std::vector<Xref> xrefs = dis.find_xrefs(addr, elf);
    
    if (xrefs.empty()) {
        std::cout << "No cross-references found to 0x" << std::hex << addr << std::dec << "\n";
        return;
    }
    
    for (const auto& xref : xrefs) {
        std::cout << "0x" << std::hex << xref.from << std::dec 
                  << ": " << xref.mnemonic << " " << xref.detail << "\n";
    }
}

void cmd_patch(ElfParser& elf, const std::string& target, const std::string& hex_bytes) {
    if (!is_hex_address(target)) {
        std::cerr << "Error: Address must be in hex format (e.g., 0x401234)\n";
        return;
    }
    
    uint64_t addr = parse_address(target);
    std::vector<uint8_t> bytes = Patcher::hex_to_bytes(hex_bytes);
    
    if (bytes.empty()) {
        return;
    }
    
    if (Patcher::apply_patch(elf, addr, bytes, true)) {
        std::cout << "Patched " << bytes.size() << " bytes at 0x" 
                  << std::hex << addr << std::dec << "\n";
    }
}

void cmd_hexdump(ElfParser& elf, const std::string& section, size_t offset, size_t length) {
    std::vector<uint8_t> data = elf.get_section_data(section);
    if (data.empty()) {
        std::cerr << "Error: Section '" << section << "' not found or empty\n";
        return;
    }
    
    if (offset >= data.size()) {
        std::cerr << "Error: Offset " << offset << " exceeds section size " << data.size() << "\n";
        return;
    }
    
    if (offset + length > data.size()) {
        length = data.size() - offset;
    }
    
    std::cout << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; i += 16) {
        std::cout << "0x" << std::setw(8) << (offset + i) << ": ";
        
        // Hex
        for (size_t j = 0; j < 16 && i + j < length; j++) {
            std::cout << std::setw(2) << (int)data[offset + i + j] << " ";
            if (j == 7) std::cout << " ";
        }
        
        // Padding
        for (size_t j = length - i; j < 16; j++) {
            std::cout << "   ";
            if (j == 7) std::cout << " ";
        }
        
        std::cout << " |";
        
        // ASCII
        for (size_t j = 0; j < 16 && i + j < length; j++) {
            char c = data[offset + i + j];
            std::cout << (isprint(c) ? c : '.');
        }
        
        std::cout << "|\n";
    }
    std::cout << std::dec << std::setfill(' ');
}

void cmd_sections(ElfParser& elf) {
    ElfInfo info = elf.get_info();
    std::cout << "Sections in binary:\n";
    for (const auto& section : info.sections) {
        Elf64_Shdr shdr;
        if (elf.get_section(section, shdr)) {
            std::cout << "  " << std::setw(20) << section 
                      << " addr=0x" << std::hex << shdr.sh_addr 
                      << " size=0x" << shdr.sh_size << std::dec
                      << " offset=0x" << std::hex << shdr.sh_offset << std::dec;
            
            if (shdr.sh_flags & SHF_EXECINSTR) {
                std::cout << " [EXEC]";
            }
            if (shdr.sh_flags & SHF_WRITE) {
                std::cout << " [WRITE]";
            }
            std::cout << "\n";
        }
    }
}

void cmd_segments(ElfParser& elf) {
    std::vector<SegmentInfo> segments = elf.get_segments();
    if (segments.empty()) {
        std::cerr << "No program segments found\n";
        return;
    }
    
    std::cout << "Program segments:\n";
    std::cout << "  Type           Offset   VirtAddr   PhysAddr   FileSiz  MemSiz   Flags Align\n";
    
    for (const auto& seg : segments) {
        std::cout << "  " << std::setw(14) << seg.type_name
                  << " 0x" << std::hex << std::setw(6) << seg.offset
                  << " 0x" << std::setw(8) << seg.vaddr
                  << " 0x" << std::setw(8) << seg.paddr
                  << " 0x" << std::setw(6) << seg.filesz
                  << " 0x" << std::setw(6) << seg.memsz
                  << " " << std::setw(5) << seg.flags_str
                  << " 0x" << std::setw(4) << seg.align << std::dec << "\n";
    }
}

void cmd_history() {
    if (command_history.empty()) {
        std::cout << "No commands in history\n";
        return;
    }
    
    std::cout << "Command history:\n";
    for (size_t i = 0; i < command_history.size(); i++) {
        std::cout << "  " << (i + 1) << "  " << command_history[i] << "\n";
    }
}

void print_interactive_help() {
    std::cout << "\n=== BINJA Interactive Mode Commands ===\n"
              << "  info                              - Show ELF information\n"
              << "  functions                         - List all functions\n"
              << "  strings [min_len]                 - Print strings (default 4)\n"
              << "  disas <func|addr>                 - Disassemble function\n"
              << "  xrefs <addr>                      - Find cross-references\n"
              << "  patch <addr> <hex>                - Patch binary\n"
              << "  hexdump <section> [offset] [len]  - Hex dump section\n"
              << "  sections                          - List all sections\n"
              << "  segments                          - List program segments\n"
              << "  help                              - Show this help\n"
              << "  history                           - Show command history\n"
              << "  !<n>                              - Repeat command n from history\n"
              << "  !!                                - Repeat last command\n"
              << "  exit / quit / Ctrl+D              - Exit binja\n"
              << "=====================================\n\n";
}

void save_to_history(const std::string& cmd) {
    if (cmd.empty()) return;
    
    std::ofstream file(HISTORY_FILE, std::ios::app);
    if (file) {
        // Add timestamp
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        file << std::ctime(&time_t) << cmd << "\n---\n";
        file.close();
    }
}

void load_history() {
    std::ifstream file(HISTORY_FILE);
    if (!file) return;
    
    command_history.clear();
    std::string line;
    bool reading_command = false;
    std::string cmd;
    
    while (std::getline(file, line)) {
        if (line == "---") {
            if (!cmd.empty()) {
                command_history.push_back(cmd);
                cmd.clear();
            }
            reading_command = false;
        } else if (reading_command) {
            if (!cmd.empty()) cmd += "\n";
            cmd += line;
        } else {
            // Skip timestamp lines
            reading_command = true;
        }
    }
    
    file.close();
}

void add_to_history(const std::string& cmd) {
    if (cmd.empty()) return;
    command_history.push_back(cmd);
    save_to_history(cmd);
}

std::string get_input() {
    std::string input;
    std::cout << "binja> ";
    std::fflush(stdout);
    
    if (!std::getline(std::cin, input)) {
        return "exit";
    }
    
    return input;
}

void signal_handler(int sig) {
    if (sig == SIGINT) {
        std::cout << "\nType 'exit' to quit\n";
        std::cout << "binja> " << std::flush;
    }
}

bool execute_command(ElfParser& elf, const std::string& input) {
    if (input.empty()) return true;
    
    // Handle history expansion
    std::string cmd = input;
    if (input == "!!") {
        if (command_history.empty()) {
            std::cerr << "No commands in history\n";
            return true;
        }
        cmd = command_history.back();
        std::cout << "Repeating: " << cmd << "\n";
    } else if (input[0] == '!') {
        try {
            size_t idx = std::stoul(input.substr(1)) - 1;
            if (idx >= command_history.size()) {
                std::cerr << "Invalid history index\n";
                return true;
            }
            cmd = command_history[idx];
            std::cout << "Repeating: " << cmd << "\n";
        } catch (...) {
            std::cerr << "Invalid history command\n";
            return true;
        }
    }
    
    // Parse command
    std::istringstream iss(cmd);
    std::string command;
    iss >> command;
    
    if (command == "exit" || command == "quit") {
        return false;
    }
    else if (command == "help") {
        print_interactive_help();
    }
    else if (command == "info") {
        cmd_info(elf);
    }
    else if (command == "functions") {
        cmd_functions(elf);
    }
    else if (command == "strings") {
        size_t min_len = 4;
        std::string len_str;
        if (iss >> len_str) {
            min_len = std::stoul(len_str);
        }
        cmd_strings(elf, min_len);
    }
    else if (command == "disas") {
        std::string target;
        if (!(iss >> target)) {
            std::cerr << "Error: Missing function name or address\n";
            return true;
        }
        Disassembler dis;
        cmd_disas(elf, dis, target);
    }
    else if (command == "xrefs") {
        std::string target;
        if (!(iss >> target)) {
            std::cerr << "Error: Missing target address\n";
            return true;
        }
        Disassembler dis;
        cmd_xrefs(elf, dis, target);
    }
    else if (command == "patch") {
        std::string target, hex_bytes;
        if (!(iss >> target >> hex_bytes)) {
            std::cerr << "Error: Missing address or hex bytes\n";
            return true;
        }
        cmd_patch(elf, target, hex_bytes);
    }
    else if (command == "hexdump") {
        std::string section;
        size_t offset = 0, length = 256;
        iss >> section;
        if (section.empty()) {
            std::cerr << "Error: Missing section name\n";
            return true;
        }
        if (iss >> offset) {
            if (iss >> length) {
                // Do nothing, length already set
            }
        }
        cmd_hexdump(elf, section, offset, length);
    }
    else if (command == "sections") {
        cmd_sections(elf);
    }
    else if (command == "segments") {
        cmd_segments(elf);
    }
    else if (command == "history") {
        cmd_history();
    }
    else if (!command.empty()) {
        std::cerr << "Unknown command: " << command << ". Type 'help' for available commands.\n";
    }
    
    return true;
}

void interactive_mode(ElfParser& elf, const std::string& binary_name) {
    std::cout << "\n╔════════════════════════╗\n";
    std::cout << "║         BINJA          ║\n";
    std::cout << "╚════════════════════════╝\n";
    std::cout << "Binary: " << binary_name << "\n";
    std::cout << "Type 'help' for available commands, 'exit' to quit\n\n";
    
    // Set signal handler for Ctrl+C
    signal(SIGINT, signal_handler);
    
    load_history();
    g_current_elf = &elf;
    
    while (true) {
        std::string input = get_input();
        
        if (input == "exit" || input == "quit" || input.empty()) {
            std::cout << "Goodbye!\n";
            break;
        }
        
        if (!input.empty()) {
            add_to_history(input);
        }
        
        if (!execute_command(elf, input)) {
            break;
        }
    }
    
    g_current_elf = nullptr;
}

void print_usage(const char* progname) {
    std::cout << "Usage: " << progname << " [binary] [command] [args...]\n\n"
              << "Interactive Mode:\n"
              << "  " << progname << " <binary>              - Start interactive REPL\n\n"
              << "Command Mode:\n"
              << "  " << progname << " <binary> <command> [args...]\n\n"
              << "Commands:\n"
              << "  info                          Print ELF header info and protections\n"
              << "  functions                     List all function symbols\n"
              << "  strings [min_len]             Print printable strings (default min_len=4)\n"
              << "  disas <function_name|address> Disassemble function\n"
              << "  xrefs <address>               Find cross-references to address\n"
              << "  patch <address> <hex_bytes>   Patch binary at address\n"
              << "  help                          Show this help\n\n"
              << "Examples:\n"
              << "  " << progname << " vuln info               # Command mode\n"
              << "  " << progname << " vuln                    # Interactive mode\n"
              << "  " << progname << " vuln disas main         # Disassemble main\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    std::string binary = argv[1];
    bool interactive = (argc == 2);
    
    // Load ELF file
    ElfParser elf;
    if (!elf.load(binary)) {
        return 1;
    }
    
    // Interactive mode
    if (interactive) {
        interactive_mode(elf, binary);
        return 0;
    }
    
    // Command mode (original functionality)
    std::string command = argv[2];
    
    if (command == "info") {
        cmd_info(elf);
    }
    else if (command == "functions") {
        cmd_functions(elf);
    }
    else if (command == "strings") {
        size_t min_len = 4;
        if (argc >= 4) {
            min_len = std::stoul(argv[3]);
        }
        cmd_strings(elf, min_len);
    }
    else if (command == "disas") {
        if (argc < 4) {
            std::cerr << "Error: Missing function name or address\n";
            return 1;
        }
        Disassembler dis;
        cmd_disas(elf, dis, argv[3]);
    }
    else if (command == "xrefs") {
        if (argc < 4) {
            std::cerr << "Error: Missing target address\n";
            return 1;
        }
        Disassembler dis;
        cmd_xrefs(elf, dis, argv[3]);
    }
    else if (command == "patch") {
        if (argc < 5) {
            std::cerr << "Error: Missing address or hex bytes\n";
            return 1;
        }
        cmd_patch(elf, argv[3], argv[4]);
    }
    else if (command == "help") {
        print_usage(argv[0]);
    }
    else {
        std::cerr << "Error: Unknown command '" << command << "'\n";
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}