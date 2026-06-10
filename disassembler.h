#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <capstone/capstone.h>

class ElfParser;

struct Instruction {
    uint64_t address;
    std::string mnemonic;
    std::string op_str;
    
    Instruction(uint64_t addr, const char* mnem, const char* ops)
        : address(addr), mnemonic(mnem), op_str(ops) {}
};

struct Xref {
    uint64_t from;
    std::string mnemonic;
    std::string detail;
    
    Xref(uint64_t f, const std::string& m, const std::string& d)
        : from(f), mnemonic(m), detail(d) {}
};

class Disassembler {
public:
    Disassembler();
    ~Disassembler();
    
    bool init(bool is_64bit, bool is_little_endian);
    void cleanup();
    
    std::vector<Instruction> disassemble(uint64_t start_addr, 
                                        const std::vector<uint8_t>& data,
                                        size_t num_instructions = 0);
    
    bool disassemble_function(const std::string& func_name, ElfParser& elf);
    bool disassemble_function(uint64_t address, ElfParser& elf);
    
    std::vector<Xref> find_xrefs(uint64_t target_addr, ElfParser& elf);
    
private:
    csh m_handle;
    bool m_initialized;
    bool m_is_64bit;
};

#endif // DISASSEMBLER_H