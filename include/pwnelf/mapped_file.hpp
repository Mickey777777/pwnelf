#pragma once

#include <pwnelf/bytes.hpp>
#include <string>

namespace pwnelf{
    class MappedFile{
        private:
        std::string path_;
        ByteView data_;

        MappedFile(std::string path, ByteView data) noexcept;
        void reset() noexcept;

        public:
        static MappedFile open(const std::string& path);

        ByteView view() const noexcept;
        const std::string& path() const noexcept;

        MappedFile(MappedFile&&) noexcept;
        MappedFile& operator=(MappedFile&&) noexcept;
        MappedFile(const MappedFile&) = delete;
        MappedFile& operator=(const MappedFile&) = delete;
        ~MappedFile();
    };
}