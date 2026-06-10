#ifndef PATCHER_H
#define PATCHER_H

#include <cstdint>
#include <string>
#include <vector>

class ElfParser;

class Patcher {
public:
    Patcher();
    ~Patcher();
    
    // In-memory patching
    static std::vector<uint8_t> patch_memory(const std::vector<uint8_t>& original,
                                             size_t offset,
                                             const std::vector<uint8_t>& new_bytes);
    
    // File-based patching
    static bool patch_file(const std::string& filename,
                          uint64_t offset,
                          const std::vector<uint8_t>& new_bytes,
                          bool create_backup = true);
    
    // High-level patch by virtual address
    static bool apply_patch(ElfParser& elf,
                           uint64_t address,
                           const std::vector<uint8_t>& new_bytes,
                           bool create_backup = true);
    
    // Parse hex string to bytes
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex);
    
private:
    static bool is_hex_char(char c);
    static uint8_t hex_char_to_byte(char c);
};

#endif // PATCHER_H