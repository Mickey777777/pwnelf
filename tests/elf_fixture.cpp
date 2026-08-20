#include "elf_fixture.hpp"

#include <fstream>

namespace fixture{
    std::vector<std::uint8_t> elf64_header_only(){
        std::vector<std::uint8_t> buf(kEhdrSize, 0);

        buf[0] = 0x7f;
        buf[1] = 'E';
        buf[2] = 'L';
        buf[3] = 'F';
        buf[kEhdrOffClass] = 2;
        buf[kEhdrOffData] = 1;
        buf[kEhdrOffVersionId] = 1;

        patch<std::uint16_t>(buf, kEhdrOffType, 2);
        patch<std::uint16_t>(buf, kEhdrOffMachine, 62);
        patch<std::uint32_t>(buf, kEhdrOffVersion, 1);
        patch<std::uint64_t>(buf, kEhdrOffEntry, 0x401000);
        patch<std::uint16_t>(buf, kEhdrOffEhsize, 64);
        patch<std::uint16_t>(buf, kEhdrOffPhentsize, 56);
        patch<std::uint16_t>(buf, kEhdrOffShentsize, 64);
        patch<std::uint16_t>(buf, kEhdrOffShstrndx, 0);

        return buf;
    }

    std::string writeTempFile(const std::string& name, const std::vector<std::uint8_t>& bytes){
        const std::string path = std::string(PWNELF_TEST_TMPDIR) + "/" + name;
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
        f.close();
        return path;
    }
}
