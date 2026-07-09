#ifndef ROP_FINDER_H
#define ROP_FINDER_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>

class ElfParser;
class Disassembler;

struct ROPGadget {
    uint64_t address;
    std::vector<uint8_t> bytes;
    std::vector<std::string> instructions;
    std::string effect;           // e.g., "pop rdi; ret", "mov rax, [rsp]; ret"
    std::vector<std::string> registers_affected;
    bool ends_with_ret;
    bool is_syscall;
    
    // For gadget chains
    uint64_t next_address;        // Where this gadget can jump to
    std::vector<uint64_t> possible_nexts;
};

struct ROPChain {
    std::vector<ROPGadget> gadgets;
    std::vector<uint64_t> addresses;
    std::string description;
    bool is_valid;
};

struct GadgetFilter {
    bool require_ret = true;
    bool require_syscall = false;
    std::vector<std::string> must_contain;
    std::vector<std::string> must_not_contain;
    int max_instructions = 8;
    uint64_t min_address = 0;
    uint64_t max_address = UINT64_MAX;
};

class ROPFinder {
public:
    ROPFinder(ElfParser& elf, Disassembler& dis);
    ~ROPFinder();
    
    // Main search functions
    std::vector<ROPGadget> find_gadgets(const GadgetFilter& filter = {});
    std::vector<ROPGadget> find_gadgets_by_pattern(const std::string& pattern);
    std::vector<ROPGadget> find_syscall_gadgets();
    
    // Specific gadget types
    std::vector<ROPGadget> find_pop_ret_gadgets();
    std::vector<ROPGadget> find_mov_ret_gadgets();
    std::vector<ROPGadget> find_xchg_ret_gadgets();
    
    // Chain building
    std::optional<ROPChain> build_chain(const std::vector<std::string>& required_effects);
    std::vector<ROPChain> find_chains(uint64_t start_addr, uint64_t end_addr, int max_depth = 10);
    
    // Utility
    std::string describe_gadget(const ROPGadget& gadget);
    void print_gadget(const ROPGadget& gadget);
    void print_gadget_table(const std::vector<ROPGadget>& gadgets);
    
    // Export
    std::string to_asm(const ROPChain& chain);
    std::string to_python_exploit(const ROPChain& chain, const std::string& payload_var = "payload");
    
private:
    // Internal search functions
    std::vector<ROPGadget> scan_executable_sections(const GadgetFilter& filter);
    std::vector<ROPGadget> scan_address_range(uint64_t start, uint64_t end, const GadgetFilter& filter);
    
    // Gadget analysis
    void analyze_gadget(ROPGadget& gadget);
    bool matches_filter(const ROPGadget& gadget, const GadgetFilter& filter);
    std::string extract_effect(const ROPGadget& gadget);
    std::vector<std::string> extract_affected_registers(const ROPGadget& gadget);
    
    // Chain building helpers
    bool can_chain(const ROPGadget& from, const ROPGadget& to);
    uint64_t get_next_address(const ROPGadget& gadget);
    
    // Caching
    void cache_gadgets(const std::vector<ROPGadget>& gadgets, const std::string& cache_key);
    std::optional<std::vector<ROPGadget>> get_cached_gadgets(const std::string& cache_key);
    
    // Private members
    ElfParser& m_elf;
    Disassembler& m_dis;
    std::unordered_map<std::string, std::vector<ROPGadget>> m_cache;
    bool m_initialized;
};

#endif // ROP_FINDER_H