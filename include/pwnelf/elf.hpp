#pragma once

#include <pwnelf/mapped_file.hpp>
#include <pwnelf/bytes.hpp>
#include <pwnelf/reader.hpp>

#include <cstdint>
#include <memory>
#include <string>

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

    class ElfFile{
        private:
        std::unique_ptr<MappedFile> owned_;
        ByteView data_;
        Reader reader_;
        std::string origin_;
        ElfHeader header_;

        ElfFile(std::unique_ptr<MappedFile> owned, ByteView data, std::string origin);
        void parse_header();

        public:
        static ElfFile load(const std::string& path);
        static ElfFile parse(ByteView data, std::string origin);

        const ElfHeader& header() const noexcept;
        const std::string& origin() const noexcept;
        const Reader& reader() const noexcept;
        ByteView data() const noexcept;
    };
}