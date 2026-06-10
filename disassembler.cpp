#include "disassembler.h"
#include "elf_parser.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <cctype>

Disassembler::Disassembler() : m_handle(0), m_initialized(false), m_is_64bit(true) {}

Disassembler::~Disassembler() {
    cleanup();
}

bool Disassembler::init(bool is_64bit, bool is_little_endian) {
    if (m_initialized) {
        cleanup();
    }
    
    m_is_64bit = is_64bit;
    cs_arch arch = CS_ARCH_X86;
    cs_mode mode;
    
    if (is_64bit) {
        mode = CS_MODE_64;
    } else {
        mode = CS_MODE_32;
    }
    
    // x86 is always little-endian in Capstone
    if (!is_little_endian) {
        std::cerr << "Warning: x86/x86-64 is always little-endian, ignoring big-endian request" << std::endl;
    }
    
    cs_err err = cs_open(arch, mode, &m_handle);
    if (err != CS_ERR_OK) {
        std::cerr << "Error: Failed to initialize Capstone: " << cs_strerror(err) << std::endl;
        return false;
    }
    
    cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
    m_initialized = true;
    
    return true;
}

void Disassembler::cleanup() {
    if (m_initialized) {
        cs_close(&m_handle);
        m_initialized = false;
    }
}

std::vector<Instruction> Disassembler::disassemble(uint64_t start_addr,
                                                   const std::vector<uint8_t>& data,
                                                   size_t num_instructions) {
    std::vector<Instruction> instructions;
    
    if (!m_initialized || data.empty()) {
        return instructions;
    }
    
    uint64_t address = start_addr;
    const uint8_t* code = data.data();
    size_t size = data.size();
    size_t count = 0;
    
    while (size > 0) {
        cs_insn* insn;
        size_t disassembled = cs_disasm(m_handle, code, size, address, 1, &insn);
        
        if (disassembled == 0) {
            break;
        }
        
        instructions.emplace_back(insn[0].address, insn[0].mnemonic, insn[0].op_str);
        
        address += insn[0].size;
        code += insn[0].size;
        size -= insn[0].size;
        count++;
        
        cs_free(insn, 1);
        
        if (num_instructions > 0 && count >= num_instructions) {
            break;
        }
    }
    
    return instructions;
}

bool Disassembler::disassemble_function(const std::string& func_name, ElfParser& elf) {
    // Find function by name
    std::vector<Symbol> functions = elf.get_functions();
    Symbol target_func;
    bool found = false;
    
    for (const auto& func : functions) {
        if (func.name == func_name) {
            target_func = func;
            found = true;
            break;
        }
    }
    
    if (!found) {
        std::cerr << "Error: Function '" << func_name << "' not found" << std::endl;
        // Suggest similar names
        std::cerr << "Available functions:" << std::endl;
        for (const auto& func : functions) {
            std::cerr << "  " << func.name << " @ 0x" << std::hex << func.address << std::dec << std::endl;
        }
        return false;
    }
    
    return disassemble_function(target_func.address, elf);
}

bool Disassembler::disassemble_function(uint64_t address, ElfParser& elf) {
    // Find which section contains this address
    Elf64_Shdr text_shdr;
    if (!elf.get_section(".text", text_shdr)) {
        std::cerr << "Error: .text section not found" << std::endl;
        return false;
    }
    
    // Get function bounds
    std::vector<Symbol> functions = elf.get_functions();
    uint64_t start = address;
    uint64_t end = text_shdr.sh_addr + text_shdr.sh_size;
    
    // Find next function
    for (const auto& func : functions) {
        if (func.address > address && func.address < end) {
            end = func.address;
            break;
        }
    }
    
    // Get function data
    uint64_t offset;
    if (!elf.virtual_to_offset(start, offset)) {
        std::cerr << "Error: Cannot find file offset for address 0x" << std::hex << address << std::dec << std::endl;
        return false;
    }
    
    // Read function bytes
    size_t size = end - start;
    
    // Get section data as a safer alternative
    std::vector<uint8_t> text_data = elf.get_section_data(".text");
    if (text_data.empty()) {
        std::cerr << "Error: Cannot read .text section data" << std::endl;
        return false;
    }
    
    // Calculate offset within section
    size_t section_offset = start - text_shdr.sh_addr;
    if (section_offset + size > text_data.size()) {
        size = text_data.size() - section_offset;
    }
    
    std::vector<uint8_t> data(text_data.begin() + section_offset, 
                               text_data.begin() + section_offset + size);
    
    // Disassemble
    std::vector<Instruction> instructions = disassemble(start, data);
    
    // Print disassembly
    std::cout << std::hex << std::setfill('0');
    for (const auto& insn : instructions) {
        std::cout << "0x" << std::setw(8) << insn.address << ":\t";
        std::cout << insn.mnemonic << " " << insn.op_str << std::endl;
    }
    std::cout << std::dec << std::setfill(' ');
    
    return true;
}

std::vector<Xref> Disassembler::find_xrefs(uint64_t target_addr, ElfParser& elf) {
    std::vector<Xref> xrefs;
    
    // Get .text section
    std::vector<uint8_t> text_data = elf.get_section_data(".text");
    if (text_data.empty()) {
        std::cerr << "Error: .text section not found" << std::endl;
        return xrefs;
    }
    
    // Get .text virtual address
    Elf64_Shdr text_shdr;
    if (!elf.get_section(".text", text_shdr)) {
        return xrefs;
    }
    
    uint64_t text_vaddr = text_shdr.sh_addr;
    
    // Disassemble all of .text
    std::vector<Instruction> instructions = disassemble(text_vaddr, text_data);
    
    // Check each instruction for references to target
    for (const auto& insn : instructions) {
        // Look for call, jmp, or mov that might reference the target
        if (insn.mnemonic == "call" || insn.mnemonic == "jmp" || 
            insn.mnemonic == "mov" || insn.mnemonic.find("j") == 0) {
            
            // Try to parse the operand as an address
            std::string op = insn.op_str;
            
            // Look for hex numbers in various formats
            size_t pos = op.find("0x");
            if (pos != std::string::npos) {
                try {
                    // Handle potential 0x prefix
                    std::string hex_str = op.substr(pos);
                    uint64_t addr = std::stoull(hex_str, nullptr, 16);
                    if (addr == target_addr) {
                        xrefs.emplace_back(insn.address, insn.mnemonic, op);
                    }
                } catch (const std::exception& e) {
                    // Ignore parsing errors for this instruction
                    continue;
                }
            }
        }
    }
    
    return xrefs;
}