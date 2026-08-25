#include <pwnelf/elf.hpp>
#include <pwnelf/error.hpp>

#include <gtest/gtest.h>

#include "elf_fixture.hpp"

#include <cstdint>
#include <cstring>
#include <optional>
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

namespace{
    std::size_t shdrOffset(const std::vector<std::uint8_t>& buf, std::size_t index){
        std::uint64_t shoff = 0;
        std::memcpy(&shoff, buf.data() + fixture::kEhdrOffShoff, sizeof(shoff));
        return static_cast<std::size_t>(shoff) + index * fixture::kShdrSize;
    }
}

TEST(ElfSections, ParsesNamesAndData){
    fixture::ElfBuilder b;
    b.add_section({".text", 1, 0x6, 0x401000, {0x90, 0xc3}, 0, 0, 0});
    b.add_section({".data", 1, 0x3, 0x404000, {0xde, 0xad}, 0, 0, 0});
    const std::vector<std::uint8_t> buf = b.build();
    const pwnelf::ElfFile elf = parse(buf);

    ASSERT_EQ(elf.sections().size(), 4u);
    EXPECT_EQ(elf.sections()[0].name, "");
    EXPECT_EQ(elf.sections()[1].name, ".text");
    EXPECT_EQ(elf.sections()[2].name, ".data");
    EXPECT_EQ(elf.sections()[3].name, ".shstrtab");

    const pwnelf::Section* text = elf.find_section(".text");
    ASSERT_NE(text, nullptr);
    EXPECT_EQ(text->index, 1u);
    EXPECT_EQ(text->addr, 0x401000u);
    EXPECT_EQ(text->size, 2u);
    EXPECT_EQ(text->flags, 0x6u);

    const pwnelf::ByteView d = elf.section_data(*text);
    ASSERT_EQ(d.size(), 2u);
    EXPECT_EQ(d[0], 0x90);
    EXPECT_EQ(d[1], 0xc3);
}

TEST(ElfSections, ReturnsNullptrForMissingSection){
    fixture::ElfBuilder b;
    b.add_section({".text", 1, 0x6, 0x401000, {0xc3}, 0, 0, 0});
    const std::vector<std::uint8_t> buf = b.build();
    EXPECT_EQ(parse(buf).find_section(".nonexistent"), nullptr);
}

TEST(ElfSections, TreatsNobitsAsEmptyWithoutRangeCheck){
    fixture::ElfBuilder b;
    b.add_section({".bss", 8, 0x3, 0x405000, {}, 0, 0, 0});
    const std::vector<std::uint8_t> buf = b.build();
    const pwnelf::ElfFile elf = parse(buf);
    const pwnelf::Section* bss = elf.find_section(".bss");
    ASSERT_NE(bss, nullptr);
    EXPECT_EQ(bss->type, 8u);
    EXPECT_TRUE(elf.section_data(*bss).empty());
}

TEST(ElfSegments, ParsesProgramHeaders){
    fixture::ElfBuilder b;
    b.add_segment({1, 5, 0x1000, 0x401000, 0x200, 0x200, 0x1000});
    b.add_segment({1, 6, 0x2000, 0x404000, 0x100, 0x180, 0x1000});
    b.add_segment({0x6474e551, 6, 0, 0, 0, 0, 0x10});
    const std::vector<std::uint8_t> buf = b.build();
    const pwnelf::ElfFile elf = parse(buf);

    ASSERT_EQ(elf.segments().size(), 3u);
    EXPECT_EQ(elf.segments()[0].type, 1u);
    EXPECT_EQ(elf.segments()[0].flags, 5u);
    EXPECT_EQ(elf.segments()[0].offset, 0x1000u);
    EXPECT_EQ(elf.segments()[0].vaddr, 0x401000u);
    EXPECT_EQ(elf.segments()[0].filesz, 0x200u);
    EXPECT_EQ(elf.segments()[1].memsz, 0x180u);
    EXPECT_EQ(elf.segments()[2].type, 0x6474e551u);
}

TEST(ElfSegments, SelectsExecutableLoadSegments){
    fixture::ElfBuilder b;
    b.add_segment({1, 5, 0x1000, 0x401000, 0x200, 0x200, 0x1000});
    b.add_segment({1, 6, 0x2000, 0x404000, 0x100, 0x100, 0x1000});
    b.add_segment({0x6474e551, 7, 0, 0, 0, 0, 0x10});
    const std::vector<std::uint8_t> buf = b.build();
    const pwnelf::ElfFile elf = parse(buf);

    const std::vector<const pwnelf::Segment*> exec = elf.executable_segments();
    ASSERT_EQ(exec.size(), 1u);
    EXPECT_EQ(exec[0]->vaddr, 0x401000u);
}

TEST(ElfAddress, TranslatesVaddrToFileOffset){
    fixture::ElfBuilder b;
    b.add_segment({1, 5, 0x1000, 0x401000, 0x200, 0x200, 0x1000});
    const std::vector<std::uint8_t> buf = b.build();
    const pwnelf::ElfFile elf = parse(buf);

    ASSERT_TRUE(elf.vaddr_to_offset(0x401000).has_value());
    EXPECT_EQ(elf.vaddr_to_offset(0x401000).value(), 0x1000u);
    EXPECT_EQ(elf.vaddr_to_offset(0x401080).value(), 0x1080u);
    EXPECT_EQ(elf.vaddr_to_offset(0x4011ff).value(), 0x11ffu);
    EXPECT_FALSE(elf.vaddr_to_offset(0x401200).has_value());
    EXPECT_FALSE(elf.vaddr_to_offset(0x300000).has_value());
    EXPECT_FALSE(elf.vaddr_to_offset(0).has_value());
}

TEST(ElfAddress, IgnoresNonLoadSegmentsWhenTranslating){
    fixture::ElfBuilder b;
    b.add_segment({0x6474e551, 7, 0x1000, 0x401000, 0x200, 0x200, 0x10});
    const std::vector<std::uint8_t> buf = b.build();
    const pwnelf::ElfFile elf = parse(buf);
    EXPECT_FALSE(elf.vaddr_to_offset(0x401000).has_value());
}

TEST(ElfSections, RejectsSectionDataPastEndOfFile){
    fixture::ElfBuilder b;
    b.add_section({".text", 1, 0x6, 0x401000, {0xc3}, 0, 0, 0});
    std::vector<std::uint8_t> buf = b.build();
    fixture::patch<std::uint64_t>(buf, shdrOffset(buf, 1) + fixture::kShdrOffSize, 0xffffffff);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfSections, RejectsSectionNameOffsetOutsideStringTable){
    fixture::ElfBuilder b;
    b.add_section({".text", 1, 0x6, 0x401000, {0xc3}, 0, 0, 0});
    std::vector<std::uint8_t> buf = b.build();
    fixture::patch<std::uint32_t>(buf, shdrOffset(buf, 1) + fixture::kShdrOffName, 0xffff);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfSections, RejectsSectionNamePastEndOfStringTable){
    fixture::ElfBuilder b;
    b.add_section({".text", 1, 0x6, 0x401000, {0xc3}, 0, 0, 0});
    std::vector<std::uint8_t> buf = b.build();
    fixture::patch<std::uint32_t>(buf, shdrOffset(buf, 1) + fixture::kShdrOffName, 30);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfSegments, KeepsVaddrAndPaddrSeparate){
    fixture::ElfBuilder b;
    b.add_segment({1, 5, 0x1000, 0x401000, 0x200, 0x200, 0x1000, 0x800000});
    const std::vector<std::uint8_t> buf = b.build();
    const pwnelf::ElfFile elf = parse(buf);

    ASSERT_EQ(elf.segments().size(), 1u);
    EXPECT_EQ(elf.segments()[0].vaddr, 0x401000u);
    EXPECT_EQ(elf.segments()[0].paddr, 0x800000u);
    ASSERT_TRUE(elf.vaddr_to_offset(0x401000).has_value());
    EXPECT_EQ(elf.vaddr_to_offset(0x401000).value(), 0x1000u);
}

TEST(ElfAddress, StopsAtFileszNotMemsz){
    fixture::ElfBuilder b;
    b.add_segment({1, 6, 0x1000, 0x404000, 0x100, 0x400, 0x1000, 0});
    const std::vector<std::uint8_t> buf = b.build();
    const pwnelf::ElfFile elf = parse(buf);

    ASSERT_EQ(elf.segments()[0].filesz, 0x100u);
    ASSERT_EQ(elf.segments()[0].memsz, 0x400u);
    ASSERT_TRUE(elf.vaddr_to_offset(0x4040ff).has_value());
    EXPECT_EQ(elf.vaddr_to_offset(0x4040ff).value(), 0x10ffu);
    EXPECT_FALSE(elf.vaddr_to_offset(0x404100).has_value());
    EXPECT_FALSE(elf.vaddr_to_offset(0x4043ff).has_value());
}

TEST(ElfAddress, DoesNotWrapForSegmentNearAddressSpaceEnd){
    fixture::ElfBuilder b;
    b.add_segment({1, 5, 0x100, 0xffffffffffffff00ULL, 0x200, 0x200, 0x1000, 0});
    const std::vector<std::uint8_t> buf = b.build();
    const pwnelf::ElfFile elf = parse(buf);

    ASSERT_TRUE(elf.vaddr_to_offset(0xffffffffffffff00ULL).has_value());
    EXPECT_EQ(elf.vaddr_to_offset(0xffffffffffffff00ULL).value(), 0x100u);
    EXPECT_FALSE(elf.vaddr_to_offset(0).has_value());
    EXPECT_FALSE(elf.vaddr_to_offset(0x100).has_value());
}

TEST(ElfSections, NobitsWithNonZeroSizeHasEmptyData){
    fixture::ElfBuilder b;
    b.add_section({".bss", 8, 0x3, 0x405000, {}, 0, 0, 0, 0x1000});
    const std::vector<std::uint8_t> buf = b.build();
    const pwnelf::ElfFile elf = parse(buf);

    const pwnelf::Section* bss = elf.find_section(".bss");
    ASSERT_NE(bss, nullptr);
    EXPECT_EQ(bss->type, 8u);
    EXPECT_EQ(bss->size, 0x1000u);
    EXPECT_TRUE(elf.section_data(*bss).empty());
}

TEST(ElfSegments, RejectsLoadSegmentContentsPastEndOfFile){
    fixture::ElfBuilder b;
    b.add_segment({1, 5, 0x100, 0x401000, 0x200, 0x200, 0x1000, 0});
    std::vector<std::uint8_t> buf = b.build();

    std::uint64_t phoff = 0;
    std::memcpy(&phoff, buf.data() + fixture::kEhdrOffPhoff, sizeof(phoff));
    fixture::patch<std::uint64_t>(buf, static_cast<std::size_t>(phoff) + fixture::kPhdrOffOffset,
                                  0x900000);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfSegments, AcceptsLoadSegmentWithoutFileContents){
    fixture::ElfBuilder b;
    b.add_segment({1, 6, 0x900000, 0x404000, 0, 0x1000, 0x1000, 0});
    const std::vector<std::uint8_t> buf = b.build();

    EXPECT_NO_THROW(parse(buf));
    const pwnelf::ElfFile elf = parse(buf);
    ASSERT_EQ(elf.segments().size(), 1u);
    EXPECT_EQ(elf.segments()[0].filesz, 0u);
    EXPECT_EQ(elf.segments()[0].memsz, 0x1000u);
}

