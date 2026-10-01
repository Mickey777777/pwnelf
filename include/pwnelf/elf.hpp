#pragma once

#include <pwnelf/mapped_file.hpp>
#include <pwnelf/bytes.hpp>
#include <pwnelf/reader.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <optional>
#include <string_view>

namespace pwnelf{
    enum class ElfType : std::uint16_t {
        None = 0,
        Rel = 1,
        Exec = 2,
        Dyn = 3,
        Core = 4
    };

    struct ElfHeader{
        ElfType type{ElfType::None};
        std::uint16_t machine{0};
        std::uint64_t entry{0};
        std::uint64_t phoff{0};
        std::uint64_t shoff{0};
        std::uint16_t phentsize{0};
        std::uint16_t phnum{0};
        std::uint16_t shentsize{0};
        std::uint16_t shnum{0};
        std::uint16_t shstrndx{0};
    };

    struct Section {
        std::string name;
        std::uint16_t index{0};
        std::uint32_t type{0};
        std::uint64_t flags{0};
        std::uint64_t addr{0};
        std::uint64_t offset{0};
        std::uint64_t size{0};
        std::uint32_t link{0};
        std::uint32_t info{0};
        std::uint64_t addralign{0};
        std::uint64_t entsize{0};
    };

    struct Segment {
        std::uint32_t type{0};
        std::uint32_t flags{0};
        std::uint64_t offset{0};
        std::uint64_t vaddr{0};
        std::uint64_t paddr{0};
        std::uint64_t filesz{0};
        std::uint64_t memsz{0};
        std::uint64_t align{0};
    };

    enum class SymbolSource {Symtab, Dynsym};
    
    struct Symbol{
        std::string name;
        std::uint64_t value{0};
        std::uint64_t size{0};
        unsigned char info{0};
        unsigned char other{0};
        std::uint16_t shndx{0};
        SymbolSource source{SymbolSource::Symtab};

        unsigned char type() const noexcept;
        unsigned char bind() const noexcept;
        bool is_function() const noexcept;
        bool is_defined() const noexcept;
    };

    class ElfFile{
        private:
        std::unique_ptr<MappedFile> owned_;
        ByteView data_;
        Reader reader_;
        std::string origin_;
        ElfHeader header_;
        std::vector<Section> sections_;
        std::vector<Segment> segment_;
        std::vector<Symbol> symbols_;
        bool has_symtab_{false};

        ElfFile(std::unique_ptr<MappedFile> owned, ByteView data, std::string origin);
        void parse_header();
        void parse_segments();
        void parse_sections();
        void parse_symbols();

        public:
        static ElfFile load(const std::string& path);
        static ElfFile parse(ByteView data, std::string origin);

        const ElfHeader& header() const noexcept;
        const std::string& origin() const noexcept;
        const Reader& reader() const noexcept;
        ByteView data() const noexcept;

        const std::vector<Section>& sections() const noexcept;
        const std::vector<Segment>& segments() const noexcept;
        const Section* find_section(std::string_view name) const noexcept;
        ByteView section_data(const Section& s) const;
        std::optional<std::uint64_t> vaddr_to_offset(std::uint64_t vaddr) const noexcept;
        std::vector<const Segment*> executable_segments() const;

        const std::vector<Symbol>& symbols() const noexcept;
        bool has_symtab() const noexcept;
        bool has_symbol(std::string_view name) const noexcept;
        const Symbol* function_at(std::uint64_t addr) const noexcept;
        const Symbol* find_function(std::string_view name) const noexcept;
    };
}