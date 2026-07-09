#include "rop_finder.h"
#include "elf_parser.h"
#include "disassembler.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <regex>
#include <set>
#include <algorithm>

ROPFinder::ROPFinder(ElfParser& elf, Disassembler& dis)
    : m_elf(elf), m_dis(dis), m_initialized(false) {
}

ROPFinder::~ROPFinder() {
}

std::vector<ROPGadget> ROPFinder::find_gadgets(const GadgetFilter& filter) {
    std::cout << "[*] Scanning for ROP gadgets..." << std::endl;
    
    std::string cache_key = "gadgets_";
    cache_key += std::to_string(filter.require_ret);
    cache_key += "_" + std::to_string(filter.require_syscall);
    cache_key += "_" + std::to_string(filter.max_instructions);
    
    if (auto cached = get_cached_gadgets(cache_key)) {
        return cached.value();
    }
    
    auto gadgets = scan_executable_sections(filter);
    cache_gadgets(gadgets, cache_key);
    
    std::cout << "[+] Found " << gadgets.size() << " gadgets" << std::endl;
    return gadgets;
}

std::vector<ROPGadget> ROPFinder::scan_executable_sections(const GadgetFilter& filter) {
    std::vector<ROPGadget> all_gadgets;
    ElfInfo info = m_elf.get_info();
    
    for (const auto& section_name : info.sections) {
        Elf64_Shdr shdr;
        if (!m_elf.get_section(section_name, shdr)) continue;
        if (!(shdr.sh_flags & SHF_EXECINSTR)) continue;
        
        auto data = m_elf.get_section_data(section_name);
        if (data.empty()) continue;
        
        std::cout << "[*] Scanning: " << section_name 
                  << " (0x" << std::hex << shdr.sh_addr 
                  << " - 0x" << (shdr.sh_addr + shdr.sh_size) << std::dec << ")" << std::endl;
        
        for (size_t offset = 0; offset < data.size(); offset++) {
            uint64_t addr = shdr.sh_addr + offset;
            std::vector<uint8_t> bytes(data.begin() + offset, data.end());
            
            for (int inst_count = 1; inst_count <= filter.max_instructions; inst_count++) {
                std::vector<uint8_t> chunk;
                size_t bytes_needed = std::min((size_t)(inst_count * 15), bytes.size());
                chunk.assign(bytes.begin(), bytes.begin() + bytes_needed);
                if (chunk.size() < 1) break;
                
                auto instructions = m_dis.disassemble(addr, chunk, inst_count);
                if (instructions.size() < (size_t)inst_count) break;
                
                const auto& last_insn = instructions.back();
                bool ends_with_ret = (last_insn.mnemonic == "ret" || 
                                      last_insn.mnemonic == "retn" ||
                                      last_insn.mnemonic == "retf");
                bool is_syscall = (last_insn.mnemonic == "syscall" || 
                                   last_insn.mnemonic == "int 0x80");
                
                if (filter.require_ret && !ends_with_ret) continue;
                if (filter.require_syscall && !is_syscall) continue;
                
                ROPGadget gadget;
                gadget.address = addr;
                gadget.ends_with_ret = ends_with_ret;
                gadget.is_syscall = is_syscall;
                
                for (const auto& insn : instructions) {
                    gadget.instructions.push_back(insn.mnemonic + " " + insn.op_str);
                }
                
                analyze_gadget(gadget);
                
                if (matches_filter(gadget, filter)) {
                    bool exists = false;
                    for (auto& existing : all_gadgets) {
                        if (existing.address == gadget.address && 
                            existing.instructions.size() <= gadget.instructions.size()) {
                            exists = true;
                            break;
                        }
                    }
                    if (!exists) {
                        all_gadgets.erase(
                            std::remove_if(all_gadgets.begin(), all_gadgets.end(),
                                [&gadget](const ROPGadget& g) {
                                    return g.address == gadget.address && 
                                           g.instructions.size() > gadget.instructions.size();
                                }),
                            all_gadgets.end()
                        );
                        all_gadgets.push_back(gadget);
                    }
                    break;
                }
            }
        }
    }
    
    std::sort(all_gadgets.begin(), all_gadgets.end(),
              [](const ROPGadget& a, const ROPGadget& b) {
                  return a.address < b.address;
              });
    
    return all_gadgets;
}

void ROPFinder::analyze_gadget(ROPGadget& gadget) {
    gadget.effect = extract_effect(gadget);
    gadget.registers_affected = extract_affected_registers(gadget);
    gadget.next_address = get_next_address(gadget);
}

std::string ROPFinder::extract_effect(const ROPGadget& gadget) {
    std::string effect;
    
    for (const auto& insn : gadget.instructions) {
        if (insn.find("pop") != std::string::npos) {
            size_t reg_pos = insn.find("pop");
            if (reg_pos != std::string::npos) {
                std::string reg = insn.substr(reg_pos + 4);
                reg.erase(0, reg.find_first_not_of(" \t"));
                reg.erase(reg.find_last_not_of(" \t") + 1);
                effect += "pop " + reg + "; ";
            }
        } else if (insn.find("mov") != std::string::npos) {
            effect += "mov; ";
        } else if (insn.find("xor") != std::string::npos) {
            effect += "xor; ";
        } else if (insn.find("add") != std::string::npos) {
            effect += "add; ";
        } else if (insn.find("sub") != std::string::npos) {
            effect += "sub; ";
        } else if (insn.find("syscall") != std::string::npos) {
            effect += "syscall; ";
        } else if (insn.find("ret") != std::string::npos) {
            effect += "ret; ";
        }
    }
    
    return effect.empty() ? "unknown" : effect;
}

std::vector<std::string> ROPFinder::extract_affected_registers(const ROPGadget& gadget) {
    std::set<std::string> registers;
    std::regex reg_pattern("(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15|eax|ebx|ecx|edx|esi|edi|ebp|esp)");
    
    for (const auto& insn : gadget.instructions) {
        std::sregex_iterator iter(insn.begin(), insn.end(), reg_pattern);
        std::sregex_iterator end;
        while (iter != end) {
            registers.insert(iter->str());
            ++iter;
        }
    }
    
    return std::vector<std::string>(registers.begin(), registers.end());
}

bool ROPFinder::matches_filter(const ROPGadget& gadget, const GadgetFilter& filter) {
    if (gadget.instructions.size() > (size_t)filter.max_instructions) return false;
    if (filter.require_ret && !gadget.ends_with_ret) return false;
    if (filter.require_syscall && !gadget.is_syscall) return false;
    
    for (const auto& pattern : filter.must_contain) {
        bool found = false;
        for (const auto& insn : gadget.instructions) {
            if (insn.find(pattern) != std::string::npos) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    
    for (const auto& pattern : filter.must_not_contain) {
        for (const auto& insn : gadget.instructions) {
            if (insn.find(pattern) != std::string::npos) {
                return false;
            }
        }
    }
    
    return true;
}

uint64_t ROPFinder::get_next_address(const ROPGadget& gadget) {
    if (gadget.ends_with_ret) return 0;
    
    const auto& last_insn = gadget.instructions.back();
    if (last_insn.find("jmp") != std::string::npos) {
        std::regex addr_pattern("0x([0-9a-fA-F]+)");
        std::smatch match;
        if (std::regex_search(last_insn, match, addr_pattern)) {
            try {
                return std::stoull(match[1].str(), nullptr, 16);
            } catch (...) {
                return 0;
            }
        }
    }
    
    return 0;
}

std::optional<ROPChain> ROPFinder::build_chain(const std::vector<std::string>& required_effects) {
    ROPChain chain;
    chain.is_valid = false;
    
    auto all_gadgets = find_gadgets({});
    if (all_gadgets.empty()) return std::nullopt;
    
    for (const auto& effect : required_effects) {
        bool found = false;
        for (const auto& gadget : all_gadgets) {
            if (gadget.effect.find(effect) != std::string::npos) {
                chain.gadgets.push_back(gadget);
                chain.addresses.push_back(gadget.address);
                found = true;
                break;
            }
        }
        if (!found) return std::nullopt;
    }
    
    chain.is_valid = true;
    chain.description = "ROP chain with " + std::to_string(chain.gadgets.size()) + " gadgets";
    return chain;
}

std::vector<ROPChain> ROPFinder::find_chains(uint64_t start_addr, uint64_t end_addr, int max_depth) {
    return std::vector<ROPChain>(); // Placeholder for future implementation
}

void ROPFinder::print_gadget(const ROPGadget& gadget) {
    std::cout << std::hex << std::setfill('0');
    std::cout << "0x" << std::setw(8) << gadget.address << ": ";
    std::cout << std::dec << "[" << gadget.instructions.size() << " instrs] ";
    std::cout << "\033[32m" << gadget.effect << "\033[0m" << std::endl;
    
    for (const auto& insn : gadget.instructions) {
        std::cout << "   " << insn << std::endl;
    }
    
    if (!gadget.registers_affected.empty()) {
        std::cout << "   Affects: ";
        for (const auto& reg : gadget.registers_affected) {
            std::cout << reg << " ";
        }
        std::cout << std::endl;
    }
}

void ROPFinder::print_gadget_table(const std::vector<ROPGadget>& gadgets) {
    if (gadgets.empty()) {
        std::cout << "No gadgets found" << std::endl;
        return;
    }
    
    std::cout << "\n" << std::setw(12) << "Address" 
              << "  " << std::setw(40) << "Effect" 
              << "  Instructions" << std::endl;
    std::cout << std::string(70, '-') << std::endl;
    
    size_t count = 0;
    for (const auto& gadget : gadgets) {
        if (count >= 50) {
            std::cout << "... and " << (gadgets.size() - count) << " more" << std::endl;
            break;
        }
        std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0') 
                  << gadget.address << std::dec << std::setfill(' ')
                  << "  " << std::setw(40) << gadget.effect.substr(0, 40)
                  << "  " << gadget.instructions.size() << std::endl;
        count++;
    }
}

std::string ROPFinder::describe_gadget(const ROPGadget& gadget) {
    return gadget.effect;
}

std::string ROPFinder::to_python_exploit(const ROPChain& chain, const std::string& payload_var) {
    std::stringstream ss;
    ss << "# ROP Chain generated by binja\n";
    ss << payload_var << " = b\"\"\n";
    
    for (const auto& addr : chain.addresses) {
        ss << payload_var << " += struct.pack(\"<Q\", 0x" 
           << std::hex << addr << std::dec << ")\n";
    }
    
    ss << "\n# Gadget chain:\n";
    for (size_t i = 0; i < chain.gadgets.size(); i++) {
        ss << "#  " << i << ": 0x" << std::hex << chain.addresses[i] 
           << std::dec << " - " << chain.gadgets[i].effect << "\n";
    }
    
    return ss.str();
}

void ROPFinder::cache_gadgets(const std::vector<ROPGadget>& gadgets, const std::string& cache_key) {
    m_cache[cache_key] = gadgets;
}

std::optional<std::vector<ROPGadget>> ROPFinder::get_cached_gadgets(const std::string& cache_key) {
    auto it = m_cache.find(cache_key);
    if (it != m_cache.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<ROPGadget> ROPFinder::find_pop_ret_gadgets() {
    GadgetFilter filter;
    filter.require_ret = true;
    filter.must_contain = {"pop"};
    filter.max_instructions = 6;
    return find_gadgets(filter);
}

std::vector<ROPGadget> ROPFinder::find_syscall_gadgets() {
    GadgetFilter filter;
    filter.require_syscall = true;
    filter.max_instructions = 10;
    return find_gadgets(filter);
}

std::vector<ROPGadget> ROPFinder::find_mov_ret_gadgets() {
    GadgetFilter filter;
    filter.require_ret = true;
    filter.must_contain = {"mov"};
    filter.max_instructions = 6;
    return find_gadgets(filter);
}