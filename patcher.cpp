#include "patcher.h"
#include "elf_parser.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

Patcher::Patcher() {}

Patcher::~Patcher() {}

std::vector<uint8_t> Patcher::patch_memory(const std::vector<uint8_t>& original,
                                           size_t offset,
                                           const std::vector<uint8_t>& new_bytes) {
    std::vector<uint8_t> result = original;
    
    if (offset + new_bytes.size() > result.size()) {
        result.resize(offset + new_bytes.size());
    }
    
    std::copy(new_bytes.begin(), new_bytes.end(), result.begin() + offset);
    return result;
}

bool Patcher::patch_file(const std::string& filename,
                        uint64_t offset,
                        const std::vector<uint8_t>& new_bytes,
                        bool create_backup) {
    // Create backup if requested
    if (create_backup) {
        std::string backup_filename = filename + ".bak";
        std::ifstream src(filename, std::ios::binary);
        std::ofstream dst(backup_filename, std::ios::binary);
        
        if (!src || !dst) {
            std::cerr << "Error: Cannot create backup file" << std::endl;
            return false;
        }
        
        dst << src.rdbuf();
        src.close();
        dst.close();
        std::cout << "Backed up original to " << backup_filename << std::endl;
    }
    
    // Open file for writing
    std::fstream file(filename, std::ios::binary | std::ios::in | std::ios::out);
    if (!file) {
        std::cerr << "Error: Cannot open file for writing" << std::endl;
        return false;
    }
    
    // Seek to offset and write
    file.seekp(offset);
    file.write(reinterpret_cast<const char*>(new_bytes.data()), new_bytes.size());
    
    if (!file) {
        std::cerr << "Error: Failed to write to file" << std::endl;
        return false;
    }
    
    file.close();
    return true;
}

bool Patcher::apply_patch(ElfParser& elf,
                         uint64_t address,
                         const std::vector<uint8_t>& new_bytes,
                         bool create_backup) {
    // Convert virtual address to file offset
    uint64_t offset;
    if (!elf.virtual_to_offset(address, offset)) {
        std::cerr << "Error: Cannot resolve address 0x" << std::hex << address 
                  << " to file offset" << std::dec << std::endl;
        return false;
    }
    
    std::cout << "Patching at offset 0x" << std::hex << offset << std::dec 
              << " (" << new_bytes.size() << " bytes)" << std::endl;
    
    return patch_file(elf.get_filename(), offset, new_bytes, create_backup);
}

bool Patcher::is_hex_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

uint8_t Patcher::hex_char_to_byte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

std::vector<uint8_t> Patcher::hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    std::string cleaned;
    
    // Remove whitespace
    for (char c : hex) {
        if (!std::isspace(c)) {
            cleaned += c;
        }
    }
    
    // Validate length
    if (cleaned.length() % 2 != 0) {
        std::cerr << "Error: Hex string must have even number of characters" << std::endl;
        return bytes;
    }
    
    // Convert
    for (size_t i = 0; i < cleaned.length(); i += 2) {
        if (!is_hex_char(cleaned[i]) || !is_hex_char(cleaned[i+1])) {
            std::cerr << "Error: Invalid hex character in string" << std::endl;
            return std::vector<uint8_t>();
        }
        
        uint8_t byte = (hex_char_to_byte(cleaned[i]) << 4) | hex_char_to_byte(cleaned[i+1]);
        bytes.push_back(byte);
    }
    
    return bytes;
}