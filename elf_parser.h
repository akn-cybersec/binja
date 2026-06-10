#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

// ELF magic bytes
#define EI_MAG0 0
#define EI_MAG1 1
#define EI_MAG2 2
#define EI_MAG3 3
#define EI_CLASS 4
#define EI_DATA 5
#define EI_VERSION 6
#define EI_PAD 7

// ELF file class
#define ELFCLASS32 1
#define ELFCLASS64 2

// ELF data encoding
#define ELFDATA2LSB 1
#define ELFDATA2MSB 2

// Section header types
#define SHT_SYMTAB 2
#define SHT_DYNSYM 11
#define SHT_STRTAB 3
#define SHT_PROGBITS 1

// Section header flags
#define SHF_EXECINSTR 0x00000004
#define SHF_WRITE 0x00000001
#define SHF_ALLOC 0x00000002

// Program header types
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_NOTE 4
#define PT_GNU_RELRO 0x6474e552
#define PT_GNU_STACK 0x6474e551

// Program header flags
#define PF_X 0x1
#define PF_W 0x2
#define PF_R 0x4

// Standard ELF structures (simplified for 64-bit)
#pragma pack(push, 1)
struct Elf64_Ehdr {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64_Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct Elf64_Sym {
    uint32_t st_name;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

struct Elf64_Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};
#pragma pack(pop)

struct Symbol {
    std::string name;
    uint64_t address;
    uint64_t size;
    std::string type;  // "FUNC", "OBJECT", "NOTYPE"
    unsigned char info;
    unsigned char other;
    uint16_t shndx;
};

struct ProtectionInfo {
    bool nx;
    bool pie;
    bool canary;
    std::string relro;  // "none", "partial", "full"
    bool aslr;          // ASLR enabled?
    bool execstack;     // Executable stack?
};

struct ElfInfo {
    uint64_t entry_point;
    std::string architecture;  // "x86" or "x86-64"
    std::string endianness;    // "little" or "big"
    std::vector<std::string> sections;
    ProtectionInfo protections;
    std::string interpreter;   // Dynamic interpreter path
    uint16_t e_type;           // ET_EXEC, ET_DYN, etc.
    uint16_t e_machine;        // Machine type
};

struct SegmentInfo {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
    std::string type_name;
    std::string flags_str;
};

class ElfParser {
public:
    ElfParser();
    ~ElfParser();
    
    // File operations
    bool load(const std::string& filename);
    void close();
    bool is_loaded() const { return m_mapped_data != nullptr; }
    
    // Section access
    bool get_section(const std::string& name, Elf64_Shdr& shdr);
    bool get_section_by_index(int idx, Elf64_Shdr& shdr);
    std::vector<uint8_t> get_section_data(const std::string& name);
    std::vector<uint8_t> get_section_data_by_index(int idx);
    std::string get_section_name(int idx);
    int get_section_count() const { return m_ehdr ? m_ehdr->e_shnum : 0; }
    
    // Program header access
    const Elf64_Phdr* get_program_headers() const { return m_phdr; }
    int get_program_header_count() const { return m_ehdr ? m_ehdr->e_phnum : 0; }
    bool get_segment(int idx, SegmentInfo& seg);
    std::vector<SegmentInfo> get_segments();
    
    // Symbol access
    std::vector<Symbol> get_symbols();
    std::vector<Symbol> get_functions();
    std::vector<Symbol> get_imported_symbols();
    std::vector<Symbol> get_exported_symbols();
    Symbol find_symbol_by_name(const std::string& name);
    Symbol find_symbol_by_address(uint64_t addr);
    
    // String extraction
    std::vector<std::string> get_strings(size_t min_len = 4);
    std::vector<std::string> get_strings_from_section(const std::string& section, size_t min_len = 4);
    
    // Information
    ElfInfo get_info();
    ProtectionInfo check_protections();
    std::string get_interpreter();
    
    // Utility
    bool is_64bit() const { return m_is_64bit; }
    bool is_little_endian() const { return m_is_little_endian; }
    bool is_executable() const;
    bool is_dynamic() const;
    bool is_stripped() const;
    uint64_t get_entry_point() const { return m_entry_point; }
    const std::string& get_filename() const { return m_filename; }
    size_t get_file_size() const { return m_file_size; }
    
    // Address conversion
    bool virtual_to_offset(uint64_t vaddr, uint64_t& offset);
    bool offset_to_virtual(uint64_t offset, uint64_t& vaddr);
    uint64_t get_base_address() const;
    
    // Function lookup
    Symbol get_function_by_address(uint64_t addr);
    
    // Raw ELF header access
    const Elf64_Ehdr* get_elf_header() const { return m_ehdr; }
    const Elf64_Shdr* get_section_headers() const { return m_shdr; }
    
    // Dynamic information
    uint64_t get_dynamic_entry(uint64_t tag);
    std::vector<uint64_t> get_plt_addresses();
    
private:
    bool parse_header();
    bool parse_section_headers();
    bool parse_program_headers();
    bool parse_dynamic_section();
    std::string get_string_from_table(uint64_t strtab_offset, uint32_t offset);
    std::string get_string_from_section(int section_idx, uint32_t offset);
    
    std::string m_filename;
    int m_fd;
    uint8_t* m_mapped_data;
    size_t m_file_size;
    
    Elf64_Ehdr* m_ehdr;
    Elf64_Shdr* m_shdr;
    Elf64_Phdr* m_phdr;
    
    bool m_is_64bit;
    bool m_is_little_endian;
    uint64_t m_entry_point;
    uint64_t m_base_address;
    
    // Cache section index by name
    std::unordered_map<std::string, int> m_section_map;
    
    // Cache data
    std::vector<uint8_t> m_section_data_cache;
    std::vector<Symbol> m_symbol_cache;
    std::vector<Symbol> m_dynamic_symbol_cache;
    bool m_symbols_loaded;
    bool m_dynamic_symbols_loaded;
    
    // Dynamic section info
    std::unordered_map<uint64_t, uint64_t> m_dynamic_entries;
    bool m_dynamic_parsed;
};
// Dynamic section entry
struct Elf64_Dyn {
    uint64_t d_tag;
    union {
        uint64_t d_val;
        uint64_t d_ptr;
    } d_un;
};
#endif // ELF_PARSER_H