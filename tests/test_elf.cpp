#include <pwnelf/elf.hpp>
#include <pwnelf/error.hpp>

#include <gtest/gtest.h>

#include "elf_fixture.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace{
    pwnelf::ElfFile parse(const std::vector<std::uint8_t>& buf){
        return pwnelf::ElfFile::parse(pwnelf::ByteView(buf.data(), buf.size()), "<fixture>");
    }
}

TEST(ElfHeader, ParsesValidHeader){
    const std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    const pwnelf::ElfFile elf = parse(buf);
    EXPECT_EQ(elf.header().type, pwnelf::ElfType::Exec);
    EXPECT_EQ(elf.header().machine, 62u);
    EXPECT_EQ(elf.header().entry, 0x401000u);
    EXPECT_EQ(elf.header().phnum, 0u);
    EXPECT_EQ(elf.header().shnum, 0u);
}

TEST(ElfHeader, ParsesSharedObjectAsDyn){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffType, 3);
    EXPECT_EQ(parse(buf).header().type, pwnelf::ElfType::Dyn);
}

TEST(ElfHeader, RemembersOrigin){
    const std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    EXPECT_EQ(parse(buf).origin(), "<fixture>");
}

TEST(ElfHeader, RejectsBadMagic){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    buf[1] = 'X';
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfHeader, RejectsFileShorterThanHeader){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    buf.resize(32);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfHeader, RejectsElf32AsUnsupported){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    buf[fixture::kEhdrOffClass] = 1;
    EXPECT_THROW(parse(buf), pwnelf::UnsupportedError);
}

TEST(ElfHeader, RejectsBigEndianAsUnsupported){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    buf[fixture::kEhdrOffData] = 2;
    EXPECT_THROW(parse(buf), pwnelf::UnsupportedError);
}

TEST(ElfHeader, RejectsNonX86WithMachineNameInMessage){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffMachine, 183);
    try{
        parse(buf);
        FAIL() << "expected UnsupportedError";
    }catch(const pwnelf::UnsupportedError& e){
        const std::string msg = e.what();
        EXPECT_NE(msg.find("AARCH64"), std::string::npos) << msg;
        EXPECT_NE(msg.find("183"), std::string::npos) << msg;
    }
}

TEST(ElfHeader, RejectsWrongEhsize){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffEhsize, 52);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfHeader, RejectsWrongPhentsizeWhenSegmentsExist){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffPhnum, 1);
    fixture::patch<std::uint64_t>(buf, fixture::kEhdrOffPhoff, fixture::kEhdrSize);
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffPhentsize, 32);
    buf.resize(fixture::kEhdrSize + fixture::kPhdrSize, 0);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfHeader, IgnoresPhentsizeWhenNoSegments){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffPhentsize, 0);
    EXPECT_NO_THROW(parse(buf));
}

TEST(ElfHeader, RejectsWrongShentsizeWhenSectionsExist){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffShnum, 1);
    fixture::patch<std::uint64_t>(buf, fixture::kEhdrOffShoff, fixture::kEhdrSize);
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffShentsize, 40);
    buf.resize(fixture::kEhdrSize + fixture::kShdrSize, 0);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfHeader, RejectsProgramHeaderTablePastEndOfFile){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffPhnum, 4);
    fixture::patch<std::uint64_t>(buf, fixture::kEhdrOffPhoff, fixture::kEhdrSize);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfHeader, RejectsSectionHeaderTablePastEndOfFile){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffShnum, 100);
    fixture::patch<std::uint64_t>(buf, fixture::kEhdrOffShoff, fixture::kEhdrSize);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfHeader, RejectsSectionTableThatOverflows){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffShnum, 0xffff);
    fixture::patch<std::uint64_t>(buf, fixture::kEhdrOffShoff, 0xfffffffffffff000ULL);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfHeader, RejectsProgramTableThatOverflows){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffPhnum, 0xffff);
    fixture::patch<std::uint64_t>(buf, fixture::kEhdrOffPhoff, 0xfffffffffffff000ULL);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfHeader, RejectsSectionTableOffsetPastEndOfFile){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffShnum, 1);
    fixture::patch<std::uint64_t>(buf, fixture::kEhdrOffShoff, 200);
    buf.resize(fixture::kEhdrSize + fixture::kShdrSize, 0);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfHeader, RejectsProgramTableOffsetThatWraps){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffPhnum, 1);
    fixture::patch<std::uint64_t>(buf, fixture::kEhdrOffPhoff, 0xffffffffffffffffULL);
    buf.resize(fixture::kEhdrSize + fixture::kShdrSize, 0);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfHeader, RejectsShstrndxOutOfRange){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffShstrndx, 5);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfHeader, RejectsShstrndxEqualToShnum){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffShnum, 1);
    fixture::patch<std::uint64_t>(buf, fixture::kEhdrOffShoff, fixture::kEhdrSize);
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffShstrndx, 1);
    buf.resize(fixture::kEhdrSize + fixture::kShdrSize, 0);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfHeader, CopiesAllHeaderFields){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    fixture::patch<std::uint64_t>(buf, fixture::kEhdrOffPhoff, 64);
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffPhnum, 2);
    fixture::patch<std::uint64_t>(buf, fixture::kEhdrOffShoff, 176);
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffShnum, 3);
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffShstrndx, 2);
    buf.resize(368, 0);

    const pwnelf::ElfFile elf = parse(buf);
    EXPECT_EQ(elf.header().type, pwnelf::ElfType::Exec);
    EXPECT_EQ(elf.header().machine, 62u);
    EXPECT_EQ(elf.header().entry, 0x401000u);
    EXPECT_EQ(elf.header().phoff, 64u);
    EXPECT_EQ(elf.header().phnum, 2u);
    EXPECT_EQ(elf.header().phentsize, 56u);
    EXPECT_EQ(elf.header().shoff, 176u);
    EXPECT_EQ(elf.header().shnum, 3u);
    EXPECT_EQ(elf.header().shentsize, 64u);
    EXPECT_EQ(elf.header().shstrndx, 2u);
}

TEST(ElfHeader, AcceptsTableEndingExactlyAtEndOfFile){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    fixture::patch<std::uint16_t>(buf, fixture::kEhdrOffShnum, 1);
    fixture::patch<std::uint64_t>(buf, fixture::kEhdrOffShoff, fixture::kEhdrSize);
    buf.resize(fixture::kEhdrSize + fixture::kShdrSize, 0);
    EXPECT_NO_THROW(parse(buf));
}

TEST(ElfHeader, AcceptsEmptyTableAtEndOfFile){
    std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    fixture::patch<std::uint64_t>(buf, fixture::kEhdrOffShoff, 128);
    buf.resize(128, 0);
    EXPECT_NO_THROW(parse(buf));
}

TEST(ElfFileLoad, ParsesFileFromDisk){
    const std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    const std::string path = fixture::writeTempFile("header_only.elf", buf);

    const pwnelf::ElfFile elf = pwnelf::ElfFile::load(path);
    EXPECT_EQ(elf.header().type, pwnelf::ElfType::Exec);
    EXPECT_EQ(elf.header().entry, 0x401000u);
    EXPECT_EQ(elf.origin(), path);
    EXPECT_EQ(elf.data().size(), buf.size());
}

TEST(ElfFileLoad, MappingOutlivesLoadCall){
    const std::vector<std::uint8_t> buf = fixture::elf64_header_only();
    const std::string path = fixture::writeTempFile("header_only.elf", buf);

    const pwnelf::ElfFile elf = pwnelf::ElfFile::load(path);
    ASSERT_EQ(elf.data().size(), fixture::kEhdrSize);
    EXPECT_EQ(elf.data()[0], 0x7f);
    EXPECT_EQ(elf.data()[1], 'E');
    EXPECT_EQ(elf.reader().size(), fixture::kEhdrSize);
}

TEST(ElfFileLoad, ReportsMissingFileAsIoError){
    EXPECT_THROW(pwnelf::ElfFile::load("/nonexistent/path/to/binary"), pwnelf::IoError);
}

TEST(ElfFileLoad, ReportsNonElfFileAsParseError){
    const std::vector<std::uint8_t> junk(64, 0x41);
    const std::string path = fixture::writeTempFile("not_an_elf.bin", junk);
    EXPECT_THROW(pwnelf::ElfFile::load(path), pwnelf::ParseError);
}
