#include "elf_parser.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <cstring>
#include <algorithm>
#include <iostream>

// 32-bit ELF structures
#pragma pack(push, 1)
struct Elf32_Ehdr {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf32_Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    uint32_t sh_addr;
    uint32_t sh_offset;
    uint32_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint32_t sh_addralign;
    uint32_t sh_entsize;
};

struct Elf32_Phdr {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
};

struct Elf32_Sym {
    uint32_t st_name;
    uint32_t st_value;
    uint32_t st_size;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t st_shndx;
};
#pragma pack(pop)

ElfParser::ElfParser() 
    : m_fd(-1), m_mapped_data(nullptr), m_file_size(0), 
      m_ehdr(nullptr), m_shdr(nullptr), m_phdr(nullptr),
      m_is_64bit(true), m_is_little_endian(true), m_entry_point(0), m_base_address(0),
      m_symbols_loaded(false), m_dynamic_symbols_loaded(false), m_dynamic_parsed(false) {}

ElfParser::~ElfParser() {
    close();
}

bool ElfParser::load(const std::string& filename) {
    m_filename = filename;
    
    m_fd = open(filename.c_str(), O_RDONLY);
    if (m_fd < 0) {
        std::cerr << "Error: Cannot open file " << filename << std::endl;
        return false;
    }
    
    struct stat st;
    if (fstat(m_fd, &st) != 0) {
        std::cerr << "Error: Cannot stat file" << std::endl;
        close();
        return false;
    }
    m_file_size = st.st_size;
    
    m_mapped_data = (uint8_t*)mmap(nullptr, m_file_size, PROT_READ, MAP_PRIVATE, m_fd, 0);
    if (m_mapped_data == MAP_FAILED) {
        std::cerr << "Error: Cannot memory map file" << std::endl;
        close();
        return false;
    }
    
    if (m_file_size < 16) {
        std::cerr << "Error: File too small" << std::endl;
        return false;
    }
    
    unsigned char* ident = m_mapped_data;
    if (ident[EI_MAG0] != 0x7f || ident[EI_MAG1] != 'E' || 
        ident[EI_MAG2] != 'L' || ident[EI_MAG3] != 'F') {
        std::cerr << "Error: Not an ELF file" << std::endl;
        return false;
    }
    
    if (ident[EI_CLASS] == ELFCLASS32) {
        m_is_64bit = false;
    } else if (ident[EI_CLASS] == ELFCLASS64) {
        m_is_64bit = true;
    } else {
        std::cerr << "Error: Unknown ELF class" << std::endl;
        return false;
    }
    
    if (ident[EI_DATA] == ELFDATA2LSB) {
        m_is_little_endian = true;
    } else if (ident[EI_DATA] == ELFDATA2MSB) {
        m_is_little_endian = false;
    } else {
        std::cerr << "Error: Unknown data encoding" << std::endl;
        return false;
    }
    
    if (!parse_header()) {
        std::cerr << "Error: Failed to parse ELF header" << std::endl;
        return false;
    }
    
    if (!parse_section_headers()) {
        std::cerr << "Warning: Could not parse section headers" << std::endl;
    }
    
    if (!parse_program_headers()) {
        std::cerr << "Warning: Could not parse program headers" << std::endl;
    }
    
    return true;
}

void ElfParser::close() {
    if (m_mapped_data && m_mapped_data != MAP_FAILED) {
        munmap(m_mapped_data, m_file_size);
        m_mapped_data = nullptr;
    }
    if (m_fd >= 0) {
        ::close(m_fd);
        m_fd = -1;
    }
    m_ehdr = nullptr;
    m_shdr = nullptr;
    m_phdr = nullptr;
}

bool ElfParser::parse_header() {
    if (!m_mapped_data) return false;
    
    if (m_is_64bit) {
        if (m_file_size < sizeof(Elf64_Ehdr)) return false;
        m_ehdr = (Elf64_Ehdr*)m_mapped_data;
        m_entry_point = m_ehdr->e_entry;
    } else {
        if (m_file_size < sizeof(Elf32_Ehdr)) return false;
        Elf32_Ehdr* ehdr32 = (Elf32_Ehdr*)m_mapped_data;
        static Elf64_Ehdr ehdr64;
        memcpy(ehdr64.e_ident, ehdr32->e_ident, 16);
        ehdr64.e_type = ehdr32->e_type;
        ehdr64.e_machine = ehdr32->e_machine;
        ehdr64.e_version = ehdr32->e_version;
        ehdr64.e_entry = ehdr32->e_entry;
        ehdr64.e_phoff = ehdr32->e_phoff;
        ehdr64.e_shoff = ehdr32->e_shoff;
        ehdr64.e_flags = ehdr32->e_flags;
        ehdr64.e_ehsize = ehdr32->e_ehsize;
        ehdr64.e_phentsize = ehdr32->e_phentsize;
        ehdr64.e_phnum = ehdr32->e_phnum;
        ehdr64.e_shentsize = ehdr32->e_shentsize;
        ehdr64.e_shnum = ehdr32->e_shnum;
        ehdr64.e_shstrndx = ehdr32->e_shstrndx;
        m_ehdr = &ehdr64;
        m_entry_point = ehdr64.e_entry;
    }
    return true;
}

bool ElfParser::parse_section_headers() {
    if (!m_ehdr || m_ehdr->e_shoff == 0 || m_ehdr->e_shnum == 0) return false;
    
    size_t header_size = m_is_64bit ? sizeof(Elf64_Shdr) : sizeof(Elf32_Shdr);
    if (m_ehdr->e_shoff + (m_ehdr->e_shnum * header_size) > m_file_size) return false;
    
    if (m_is_64bit) {
        m_shdr = (Elf64_Shdr*)(m_mapped_data + m_ehdr->e_shoff);
    } else {
        Elf32_Shdr* shdr32 = (Elf32_Shdr*)(m_mapped_data + m_ehdr->e_shoff);
        static std::vector<Elf64_Shdr> shdr64_vec;
        shdr64_vec.resize(m_ehdr->e_shnum);
        for (int i = 0; i < m_ehdr->e_shnum; i++) {
            shdr64_vec[i].sh_name = shdr32[i].sh_name;
            shdr64_vec[i].sh_type = shdr32[i].sh_type;
            shdr64_vec[i].sh_flags = shdr32[i].sh_flags;
            shdr64_vec[i].sh_addr = shdr32[i].sh_addr;
            shdr64_vec[i].sh_offset = shdr32[i].sh_offset;
            shdr64_vec[i].sh_size = shdr32[i].sh_size;
            shdr64_vec[i].sh_link = shdr32[i].sh_link;
            shdr64_vec[i].sh_info = shdr32[i].sh_info;
            shdr64_vec[i].sh_addralign = shdr32[i].sh_addralign;
            shdr64_vec[i].sh_entsize = shdr32[i].sh_entsize;
        }
        m_shdr = shdr64_vec.data();
    }
    
    if (m_ehdr->e_shstrndx < m_ehdr->e_shnum) {
        Elf64_Shdr* shstrtab = &m_shdr[m_ehdr->e_shstrndx];
        if (shstrtab->sh_offset + shstrtab->sh_size <= m_file_size) {
            char* strtab = (char*)(m_mapped_data + shstrtab->sh_offset);
            for (int i = 0; i < m_ehdr->e_shnum; i++) {
                if (m_shdr[i].sh_name < shstrtab->sh_size) {
                    const char* name = strtab + m_shdr[i].sh_name;
                    m_section_map[name] = i;
                }
            }
        }
    }
    return true;
}

bool ElfParser::parse_program_headers() {
    if (!m_ehdr || m_ehdr->e_phoff == 0 || m_ehdr->e_phnum == 0) return false;
    
    size_t header_size = m_is_64bit ? sizeof(Elf64_Phdr) : sizeof(Elf32_Phdr);
    if (m_ehdr->e_phoff + (m_ehdr->e_phnum * header_size) > m_file_size) return false;
    
    if (m_is_64bit) {
        m_phdr = (Elf64_Phdr*)(m_mapped_data + m_ehdr->e_phoff);
    } else {
        Elf32_Phdr* phdr32 = (Elf32_Phdr*)(m_mapped_data + m_ehdr->e_phoff);
        static std::vector<Elf64_Phdr> phdr64_vec;
        phdr64_vec.resize(m_ehdr->e_phnum);
        for (int i = 0; i < m_ehdr->e_phnum; i++) {
            phdr64_vec[i].p_type = phdr32[i].p_type;
            phdr64_vec[i].p_flags = phdr32[i].p_flags;
            phdr64_vec[i].p_offset = phdr32[i].p_offset;
            phdr64_vec[i].p_vaddr = phdr32[i].p_vaddr;
            phdr64_vec[i].p_paddr = phdr32[i].p_paddr;
            phdr64_vec[i].p_filesz = phdr32[i].p_filesz;
            phdr64_vec[i].p_memsz = phdr32[i].p_memsz;
            phdr64_vec[i].p_align = phdr32[i].p_align;
        }
        m_phdr = phdr64_vec.data();
    }
    return true;
}

bool ElfParser::get_section(const std::string& name, Elf64_Shdr& shdr) {
    auto it = m_section_map.find(name);
    if (it == m_section_map.end() || !m_shdr) return false;
    if (it->second >= m_ehdr->e_shnum) return false;
    shdr = m_shdr[it->second];
    return true;
}

bool ElfParser::get_section_by_index(int idx, Elf64_Shdr& shdr) {
    if (!m_shdr || idx < 0 || idx >= m_ehdr->e_shnum) return false;
    shdr = m_shdr[idx];
    return true;
}

std::vector<uint8_t> ElfParser::get_section_data(const std::string& name) {
    Elf64_Shdr shdr;
    if (!get_section(name, shdr)) return std::vector<uint8_t>();
    if (shdr.sh_offset + shdr.sh_size > m_file_size) return std::vector<uint8_t>();
    std::vector<uint8_t> data(shdr.sh_size);
    memcpy(data.data(), m_mapped_data + shdr.sh_offset, shdr.sh_size);
    return data;
}

std::vector<uint8_t> ElfParser::get_section_data_by_index(int idx) {
    Elf64_Shdr shdr;
    if (!get_section_by_index(idx, shdr)) return std::vector<uint8_t>();
    if (shdr.sh_offset + shdr.sh_size > m_file_size) return std::vector<uint8_t>();
    std::vector<uint8_t> data(shdr.sh_size);
    memcpy(data.data(), m_mapped_data + shdr.sh_offset, shdr.sh_size);
    return data;
}

std::string ElfParser::get_section_name(int idx) {
    if (!m_shdr || idx < 0 || idx >= m_ehdr->e_shnum) return "";
    if (m_ehdr->e_shstrndx >= m_ehdr->e_shnum) return "";
    Elf64_Shdr* shstrtab = &m_shdr[m_ehdr->e_shstrndx];
    if (shstrtab->sh_offset + m_shdr[idx].sh_name >= m_file_size) return "";
    char* strtab = (char*)(m_mapped_data + shstrtab->sh_offset);
    return std::string(strtab + m_shdr[idx].sh_name);
}

std::vector<Symbol> ElfParser::get_symbols() {
    if (m_symbols_loaded) return m_symbol_cache;
    
    m_symbol_cache.clear();
    m_symbols_loaded = true;
    
    const char* symtab_names[] = {".symtab", ".dynsym"};
    
    for (const char* symtab_name : symtab_names) {
        Elf64_Shdr symtab_shdr;
        if (!get_section(symtab_name, symtab_shdr)) continue;
        
        Elf64_Shdr strtab_shdr = {};
        bool has_strtab = false;
        
        if (get_section(".strtab", strtab_shdr)) {
            has_strtab = true;
        } else if (symtab_shdr.sh_link < m_ehdr->e_shnum) {
            strtab_shdr = m_shdr[symtab_shdr.sh_link];
            has_strtab = true;
        }
        
        if (!has_strtab) continue;
        if (strtab_shdr.sh_offset + strtab_shdr.sh_size > m_file_size) continue;
        
        char* strtab = (char*)(m_mapped_data + strtab_shdr.sh_offset);
        
        if (m_is_64bit) {
            Elf64_Sym* symtab = (Elf64_Sym*)(m_mapped_data + symtab_shdr.sh_offset);
            size_t num_syms = symtab_shdr.sh_size / symtab_shdr.sh_entsize;
            
            for (size_t i = 0; i < num_syms; i++) {
                Elf64_Sym& sym = symtab[i];
                if (sym.st_name == 0 || sym.st_name >= strtab_shdr.sh_size) continue;
                
                const char* name = strtab + sym.st_name;
                std::string type_str;
                unsigned char type = sym.st_info & 0xf;
                
                if (type == 2) type_str = "FUNC";
                else if (type == 1) type_str = "OBJECT";
                else type_str = "NOTYPE";
                
                Symbol sym_obj;
                sym_obj.name = std::string(name);
                sym_obj.address = sym.st_value;
                sym_obj.size = sym.st_size;
                sym_obj.type = type_str;
                sym_obj.info = sym.st_info;
                sym_obj.other = sym.st_other;
                sym_obj.shndx = sym.st_shndx;
                m_symbol_cache.push_back(sym_obj);
            }
        } else {
            Elf32_Sym* symtab = (Elf32_Sym*)(m_mapped_data + symtab_shdr.sh_offset);
            size_t num_syms = symtab_shdr.sh_size / sizeof(Elf32_Sym);
            
            for (size_t i = 0; i < num_syms; i++) {
                Elf32_Sym& sym = symtab[i];
                if (sym.st_name == 0 || sym.st_name >= strtab_shdr.sh_size) continue;
                
                const char* name = strtab + sym.st_name;
                std::string type_str;
                unsigned char type = sym.st_info & 0xf;
                
                if (type == 2) type_str = "FUNC";
                else if (type == 1) type_str = "OBJECT";
                else type_str = "NOTYPE";
                
                Symbol sym_obj;
                sym_obj.name = std::string(name);
                sym_obj.address = sym.st_value;
                sym_obj.size = sym.st_size;
                sym_obj.type = type_str;
                sym_obj.info = sym.st_info;
                sym_obj.other = sym.st_other;
                sym_obj.shndx = sym.st_shndx;
                m_symbol_cache.push_back(sym_obj);
            }
        }
        
        if (!m_symbol_cache.empty()) break;
    }
    
    std::sort(m_symbol_cache.begin(), m_symbol_cache.end(),
              [](const Symbol& a, const Symbol& b) { return a.address < b.address; });
    
    return m_symbol_cache;
}

std::vector<Symbol> ElfParser::get_functions() {
    std::vector<Symbol> all_syms = get_symbols();
    std::vector<Symbol> functions;
    
    for (const auto& sym : all_syms) {
        if (sym.type == "FUNC" && sym.address != 0) {
            functions.push_back(sym);
        }
    }
    return functions;
}

std::vector<std::string> ElfParser::get_strings(size_t min_len) {
    std::vector<std::string> strings;
    const char* sections[] = {".rodata", ".data"};
    
    for (const char* section_name : sections) {
        std::vector<uint8_t> data = get_section_data(section_name);
        if (data.empty()) continue;
        
        std::string current;
        for (size_t i = 0; i < data.size(); i++) {
            char c = data[i];
            if (c >= 0x20 && c <= 0x7e) {
                current += c;
            } else {
                if (current.size() >= min_len) {
                    strings.push_back(current);
                }
                current.clear();
            }
        }
        if (current.size() >= min_len) {
            strings.push_back(current);
        }
    }
    return strings;
}

std::vector<std::string> ElfParser::get_strings_from_section(const std::string& section, size_t min_len) {
    std::vector<std::string> strings;
    std::vector<uint8_t> data = get_section_data(section);
    if (data.empty()) return strings;
    
    std::string current;
    for (size_t i = 0; i < data.size(); i++) {
        char c = data[i];
        if (c >= 0x20 && c <= 0x7e) {
            current += c;
        } else {
            if (current.size() >= min_len) {
                strings.push_back(current);
            }
            current.clear();
        }
    }
    if (current.size() >= min_len) {
        strings.push_back(current);
    }
    return strings;
}

ElfInfo ElfParser::get_info() {
    ElfInfo info;
    info.entry_point = m_entry_point;
    info.architecture = m_is_64bit ? "x86-64" : "x86";
    info.endianness = m_is_little_endian ? "little" : "big";
    info.protections = check_protections();
    
    for (const auto& pair : m_section_map) {
        info.sections.push_back(pair.first);
    }
    return info;
}

ProtectionInfo ElfParser::check_protections() {
    ProtectionInfo info;
    info.nx = true;
    info.pie = (m_ehdr->e_type == 3);
    info.canary = false;
    info.relro = "none";
    
    if (m_phdr) {
        for (int i = 0; i < m_ehdr->e_phnum; i++) {
            if (m_phdr[i].p_type == PT_GNU_STACK) {
                info.nx = !(m_phdr[i].p_flags & PF_X);
            }
            if (m_phdr[i].p_type == PT_GNU_RELRO) {
                info.relro = "full";
            }
        }
    }
    
    std::vector<Symbol> syms = get_symbols();
    for (const auto& sym : syms) {
        if (sym.name == "__stack_chk_fail") {
            info.canary = true;
            break;
        }
    }
    return info;
}

bool ElfParser::virtual_to_offset(uint64_t vaddr, uint64_t& offset) {
    if (!m_phdr) return false;
    for (int i = 0; i < m_ehdr->e_phnum; i++) {
        if (m_phdr[i].p_type == PT_LOAD &&
            vaddr >= m_phdr[i].p_vaddr &&
            vaddr < m_phdr[i].p_vaddr + m_phdr[i].p_memsz) {
            offset = m_phdr[i].p_offset + (vaddr - m_phdr[i].p_vaddr);
            return true;
        }
    }
    return false;
}

bool ElfParser::offset_to_virtual(uint64_t offset, uint64_t& vaddr) {
    if (!m_phdr) return false;
    for (int i = 0; i < m_ehdr->e_phnum; i++) {
        if (m_phdr[i].p_type == PT_LOAD &&
            offset >= m_phdr[i].p_offset &&
            offset < m_phdr[i].p_offset + m_phdr[i].p_filesz) {
            vaddr = m_phdr[i].p_vaddr + (offset - m_phdr[i].p_offset);
            return true;
        }
    }
    return false;
}

uint64_t ElfParser::get_base_address() const {
    if (!m_phdr) return 0;
    for (int i = 0; i < m_ehdr->e_phnum; i++) {
        if (m_phdr[i].p_type == PT_LOAD) {
            return m_phdr[i].p_vaddr - m_phdr[i].p_offset;
        }
    }
    return 0;
}

Symbol ElfParser::get_function_by_address(uint64_t addr) {
    std::vector<Symbol> functions = get_functions();
    for (const auto& func : functions) {
        if (func.address <= addr && addr < func.address + func.size) {
            return func;
        }
    }
    Symbol empty;
    empty.address = 0;
    empty.size = 0;
    return empty;
}

std::vector<SegmentInfo> ElfParser::get_segments() {
    std::vector<SegmentInfo> segments;
    if (!m_phdr) return segments;
    
    for (int i = 0; i < m_ehdr->e_phnum; i++) {
        SegmentInfo seg;
        seg.type = m_phdr[i].p_type;
        seg.flags = m_phdr[i].p_flags;
        seg.offset = m_phdr[i].p_offset;
        seg.vaddr = m_phdr[i].p_vaddr;
        seg.paddr = m_phdr[i].p_paddr;
        seg.filesz = m_phdr[i].p_filesz;
        seg.memsz = m_phdr[i].p_memsz;
        seg.align = m_phdr[i].p_align;
        
        switch (seg.type) {
            case PT_LOAD: seg.type_name = "LOAD"; break;
            case PT_DYNAMIC: seg.type_name = "DYNAMIC"; break;
            case PT_INTERP: seg.type_name = "INTERP"; break;
            case PT_GNU_RELRO: seg.type_name = "GNU_RELRO"; break;
            case PT_GNU_STACK: seg.type_name = "GNU_STACK"; break;
            default: seg.type_name = "UNKNOWN";
        }
        
        seg.flags_str = "";
        if (seg.flags & PF_R) seg.flags_str += "R";
        if (seg.flags & PF_W) seg.flags_str += "W";
        if (seg.flags & PF_X) seg.flags_str += "E";
        
        segments.push_back(seg);
    }
    return segments;
}

bool ElfParser::get_segment(int idx, SegmentInfo& seg) {
    if (!m_phdr || idx >= m_ehdr->e_phnum) return false;
    
    seg.type = m_phdr[idx].p_type;
    seg.flags = m_phdr[idx].p_flags;
    seg.offset = m_phdr[idx].p_offset;
    seg.vaddr = m_phdr[idx].p_vaddr;
    seg.paddr = m_phdr[idx].p_paddr;
    seg.filesz = m_phdr[idx].p_filesz;
    seg.memsz = m_phdr[idx].p_memsz;
    seg.align = m_phdr[idx].p_align;
    return true;
}

std::vector<Symbol> ElfParser::get_imported_symbols() {
    std::vector<Symbol> imported;
    std::vector<Symbol> all_syms = get_symbols();
    for (const auto& sym : all_syms) {
        if (sym.shndx == 0) {
            imported.push_back(sym);
        }
    }
    return imported;
}

std::vector<Symbol> ElfParser::get_exported_symbols() {
    std::vector<Symbol> exported;
    std::vector<Symbol> all_syms = get_symbols();
    for (const auto& sym : all_syms) {
        if (sym.shndx != 0 && sym.address != 0) {
            exported.push_back(sym);
        }
    }
    return exported;
}

Symbol ElfParser::find_symbol_by_name(const std::string& name) {
    std::vector<Symbol> all_syms = get_symbols();
    for (const auto& sym : all_syms) {
        if (sym.name == name) return sym;
    }
    Symbol empty;
    empty.address = 0;
    return empty;
}

Symbol ElfParser::find_symbol_by_address(uint64_t addr) {
    std::vector<Symbol> all_syms = get_symbols();
    for (const auto& sym : all_syms) {
        if (sym.address == addr) return sym;
    }
    Symbol empty;
    empty.address = 0;
    return empty;
}

std::string ElfParser::get_interpreter() {
    if (!m_phdr) return "";
    for (int i = 0; i < m_ehdr->e_phnum; i++) {
        if (m_phdr[i].p_type == PT_INTERP) {
            return std::string((char*)(m_mapped_data + m_phdr[i].p_offset));
        }
    }
    return "";
}

bool ElfParser::is_executable() const {
    return m_ehdr && m_ehdr->e_type == 2;
}

bool ElfParser::is_dynamic() const {
    if (!m_phdr) return false;
    for (int i = 0; i < m_ehdr->e_phnum; i++) {
        if (m_phdr[i].p_type == PT_DYNAMIC) return true;
    }
    return false;
}

bool ElfParser::is_stripped() const {
    return m_section_map.find(".symtab") == m_section_map.end();
}

bool ElfParser::parse_dynamic_section() {
    if (m_dynamic_parsed) return true;
    m_dynamic_parsed = true;
    return false;
}

uint64_t ElfParser::get_dynamic_entry(uint64_t tag) {
    return 0;
}

std::vector<uint64_t> ElfParser::get_plt_addresses() {
    return std::vector<uint64_t>();
}

std::string ElfParser::get_string_from_table(uint64_t strtab_offset, uint32_t offset) {
    if (offset == 0 || strtab_offset + offset >= m_file_size) return "";
    return std::string((char*)(m_mapped_data + strtab_offset + offset));
}

std::string ElfParser::get_string_from_section(int section_idx, uint32_t offset) {
    Elf64_Shdr shdr;
    if (!get_section_by_index(section_idx, shdr)) return "";
    return get_string_from_table(shdr.sh_offset, offset);
}