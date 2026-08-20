#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
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

    std::vector<std::uint8_t> elf64_header_only();

    std::string writeTempFile(const std::string& name, const std::vector<std::uint8_t>& bytes);

    template <class T>
    void patch(std::vector<std::uint8_t>& buf, std::size_t offset, T value){
        std::memcpy(buf.data() + offset, &value, sizeof(T));
    }
}
