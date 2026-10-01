#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace fixture{
    inline constexpr std::size_t kEhdrOffClass     = 4;
    inline constexpr std::size_t kEhdrOffData      = 5;
    inline constexpr std::size_t kEhdrOffVersionId = 6;
    inline constexpr std::size_t kEhdrOffType      = 16;
    inline constexpr std::size_t kEhdrOffMachine   = 18;
    inline constexpr std::size_t kEhdrOffVersion   = 20;
    inline constexpr std::size_t kEhdrOffEntry     = 24;
    inline constexpr std::size_t kEhdrOffPhoff     = 32;
    inline constexpr std::size_t kEhdrOffShoff     = 40;
    inline constexpr std::size_t kEhdrOffEhsize    = 52;
    inline constexpr std::size_t kEhdrOffPhentsize = 54;
    inline constexpr std::size_t kEhdrOffPhnum     = 56;
    inline constexpr std::size_t kEhdrOffShentsize = 58;
    inline constexpr std::size_t kEhdrOffShnum     = 60;
    inline constexpr std::size_t kEhdrOffShstrndx  = 62;

    inline constexpr std::size_t kEhdrSize = 64;
    inline constexpr std::size_t kPhdrSize = 56;
    inline constexpr std::size_t kShdrSize = 64;

    inline constexpr std::size_t kPhdrOffType   = 0;
    inline constexpr std::size_t kPhdrOffFlags  = 4;
    inline constexpr std::size_t kPhdrOffOffset = 8;
    inline constexpr std::size_t kPhdrOffVaddr  = 16;
    inline constexpr std::size_t kPhdrOffFilesz = 32;
    inline constexpr std::size_t kPhdrOffMemsz  = 40;

    inline constexpr std::size_t kShdrOffName   = 0;
    inline constexpr std::size_t kShdrOffType   = 4;
    inline constexpr std::size_t kShdrOffFlags  = 8;
    inline constexpr std::size_t kShdrOffAddr   = 16;
    inline constexpr std::size_t kShdrOffOffset = 24;
    inline constexpr std::size_t kShdrOffSize   = 32;
    inline constexpr std::size_t kShdrOffLink   = 40;
    inline constexpr std::size_t kShdrOffEntsize = 56;

    inline constexpr std::size_t kSymSize      = 24;
    inline constexpr std::size_t kSymOffName   = 0;

    std::vector<std::uint8_t> elf64_header_only();

    std::string writeTempFile(const std::string& name, const std::vector<std::uint8_t>& bytes);

    template <class T>
    void patch(std::vector<std::uint8_t>& buf, std::size_t offset, T value){
        std::memcpy(buf.data() + offset, &value, sizeof(T));
    }

    struct SectionSpec{
        std::string name;
        std::uint32_t type{1};
        std::uint64_t flags{0};
        std::uint64_t addr{0};
        std::vector<std::uint8_t> data;
        std::uint32_t link{0};
        std::uint32_t info{0};
        std::uint64_t entsize{0};
        std::uint64_t size{0};
    };

    struct SegmentSpec{
        std::uint32_t type{1};
        std::uint32_t flags{4};
        std::uint64_t offset{0};
        std::uint64_t vaddr{0};
        std::uint64_t filesz{0};
        std::uint64_t memsz{0};
        std::uint64_t align{0x1000};
        std::uint64_t paddr{0};
    };

    class ElfBuilder{
        private:
        std::uint16_t type_{2};
        std::uint64_t entry_{0x401000};
        std::vector<SectionSpec> sections_;
        std::vector<SegmentSpec> segments_;

        public:
        ElfBuilder& set_type(std::uint16_t type);
        ElfBuilder& set_entry(std::uint64_t entry);
        ElfBuilder& add_section(SectionSpec spec);
        ElfBuilder& add_segment(SegmentSpec spec);
        std::vector<std::uint8_t> build() const;
    };

    struct SymSpec{
        std::string name;
        std::uint64_t value{0};
        std::uint64_t size{0};
        unsigned char info{0};
        std::uint16_t shndx{0};
    };

    std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>
    build_symtab(const std::vector<SymSpec>& syms);
}