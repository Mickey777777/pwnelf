#include <pwnelf/elf.hpp>
#include <pwnelf/elf_type.hpp>
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

namespace{
    constexpr unsigned char kGlobalFunc = 0x12;
    constexpr unsigned char kGlobalObject = 0x11;
    constexpr std::size_t kSymtabIndex = 2;

    std::vector<std::uint8_t> elfWithSymtab(const std::vector<fixture::SymSpec>& syms,
                                            std::uint32_t symtab_type = 2,
                                            const char* symtab_name = ".symtab",
                                            const char* strtab_name = ".strtab"){
        auto [symdata, strdata] = fixture::build_symtab(syms);
        fixture::ElfBuilder b;
        b.add_section({".text", 1, 0x6, 0x401000, {0x90, 0xc3}, 0, 0, 0});
        b.add_section({symtab_name, symtab_type, 0, 0, symdata, 3, 1, fixture::kSymSize});
        b.add_section({strtab_name, 3, 0, 0, strdata, 0, 0, 0});
        return b.build();
    }

    const pwnelf::Symbol* findSymbol(const pwnelf::ElfFile& elf, const std::string& name){
        for(const pwnelf::Symbol& s : elf.symbols()){
            if(s.name == name) return &s;
        }
        return nullptr;
    }
}

TEST(ElfSymbols, ParsesSymtabEntries){
    const std::vector<std::uint8_t> buf = elfWithSymtab({
        {"main", 0x401000, 0x20, kGlobalFunc, 1},
        {"gvar", 0x404000, 0x08, kGlobalObject, 1},
    });
    const pwnelf::ElfFile elf = parse(buf);

    EXPECT_TRUE(elf.has_symtab());
    ASSERT_EQ(elf.symbols().size(), 3u);
    EXPECT_EQ(elf.symbols()[0].name, "");

    const pwnelf::Symbol* main_sym = elf.find_function("main");
    ASSERT_NE(main_sym, nullptr);
    EXPECT_EQ(main_sym->value, 0x401000u);
    EXPECT_EQ(main_sym->size, 0x20u);
    EXPECT_EQ(main_sym->shndx, 1u);
    EXPECT_EQ(main_sym->type(), pwnelf::STT_FUNC);
    EXPECT_EQ(main_sym->bind(), pwnelf::STB_GLOBAL);
    EXPECT_EQ(main_sym->source, pwnelf::SymbolSource::Symtab);
    EXPECT_TRUE(main_sym->is_defined());
    EXPECT_TRUE(main_sym->is_function());
}

TEST(ElfSymbols, DoesNotTreatObjectSymbolAsFunction){
    const std::vector<std::uint8_t> buf = elfWithSymtab({{"gvar", 0x404000, 8, kGlobalObject, 1}});
    const pwnelf::ElfFile elf = parse(buf);

    EXPECT_TRUE(elf.has_symbol("gvar"));
    EXPECT_EQ(elf.find_function("gvar"), nullptr);
    ASSERT_NE(findSymbol(elf, "gvar"), nullptr);
    EXPECT_EQ(findSymbol(elf, "gvar")->type(), pwnelf::STT_OBJECT);
}

TEST(ElfSymbols, DoesNotTreatUndefinedSymbolAsFunction){
    const std::vector<std::uint8_t> buf = elfWithSymtab({{"printf", 0, 0x10, kGlobalFunc, 0}});
    const pwnelf::ElfFile elf = parse(buf);

    EXPECT_TRUE(elf.has_symbol("printf"));
    ASSERT_NE(findSymbol(elf, "printf"), nullptr);
    EXPECT_FALSE(findSymbol(elf, "printf")->is_defined());
    EXPECT_EQ(elf.find_function("printf"), nullptr);
}

TEST(ElfSymbols, DoesNotTreatZeroSizeFunctionAsFunction){
    const std::vector<std::uint8_t> buf = elfWithSymtab({{"_start", 0x401000, 0, kGlobalFunc, 1}});
    const pwnelf::ElfFile elf = parse(buf);

    EXPECT_TRUE(elf.has_symbol("_start"));
    EXPECT_EQ(elf.find_function("_start"), nullptr);
    EXPECT_EQ(elf.function_at(0x401000), nullptr);
}

TEST(ElfSymbols, FindsFunctionContainingAddress){
    const std::vector<std::uint8_t> buf = elfWithSymtab({
        {"first", 0x401000, 0x20, kGlobalFunc, 1},
        {"second", 0x401020, 0x10, kGlobalFunc, 1},
    });
    const pwnelf::ElfFile elf = parse(buf);

    ASSERT_NE(elf.function_at(0x401000), nullptr);
    EXPECT_EQ(elf.function_at(0x401000)->name, "first");
    ASSERT_NE(elf.function_at(0x40101f), nullptr);
    EXPECT_EQ(elf.function_at(0x40101f)->name, "first");
    ASSERT_NE(elf.function_at(0x401020), nullptr);
    EXPECT_EQ(elf.function_at(0x401020)->name, "second");
    ASSERT_NE(elf.function_at(0x40102f), nullptr);
    EXPECT_EQ(elf.function_at(0x40102f)->name, "second");
    EXPECT_EQ(elf.function_at(0x401030), nullptr);
    EXPECT_EQ(elf.function_at(0x400fff), nullptr);
}

TEST(ElfSymbols, DoesNotWrapForFunctionNearAddressSpaceEnd){
    const std::vector<std::uint8_t> buf = elfWithSymtab({
        {"edge", 0xfffffffffffffff0ULL, 0x20, kGlobalFunc, 1},
    });
    const pwnelf::ElfFile elf = parse(buf);

    ASSERT_NE(elf.function_at(0xfffffffffffffff8ULL), nullptr);
    EXPECT_EQ(elf.function_at(0xfffffffffffffff8ULL)->name, "edge");
    EXPECT_EQ(elf.function_at(0), nullptr);
    EXPECT_EQ(elf.function_at(0x8), nullptr);
}

TEST(ElfSymbols, ReportsStrippedWhenOnlyDynsymExists){
    const std::vector<std::uint8_t> buf =
        elfWithSymtab({{"printf", 0, 0, kGlobalFunc, 0}}, 11, ".dynsym", ".dynstr");
    const pwnelf::ElfFile elf = parse(buf);

    EXPECT_FALSE(elf.has_symtab());
    EXPECT_TRUE(elf.has_symbol("printf"));
    ASSERT_NE(findSymbol(elf, "printf"), nullptr);
    EXPECT_EQ(findSymbol(elf, "printf")->source, pwnelf::SymbolSource::Dynsym);
}

TEST(ElfSymbols, MergesSymtabAndDynsym){
    auto [symdata, strdata] = fixture::build_symtab({{"main", 0x401000, 0x20, kGlobalFunc, 1}});
    auto [dyndata, dynstr] = fixture::build_symtab({{"puts", 0, 0, kGlobalFunc, 0}});
    fixture::ElfBuilder b;
    b.add_section({".text", 1, 0x6, 0x401000, {0x90, 0xc3}, 0, 0, 0});
    b.add_section({".symtab", 2, 0, 0, symdata, 3, 1, fixture::kSymSize});
    b.add_section({".strtab", 3, 0, 0, strdata, 0, 0, 0});
    b.add_section({".dynsym", 11, 0x2, 0, dyndata, 5, 1, fixture::kSymSize});
    b.add_section({".dynstr", 3, 0x2, 0, dynstr, 0, 0, 0});
    const std::vector<std::uint8_t> buf = b.build();
    const pwnelf::ElfFile elf = parse(buf);

    EXPECT_TRUE(elf.has_symtab());
    EXPECT_EQ(elf.symbols().size(), 4u);
    ASSERT_NE(findSymbol(elf, "main"), nullptr);
    EXPECT_EQ(findSymbol(elf, "main")->source, pwnelf::SymbolSource::Symtab);
    ASSERT_NE(findSymbol(elf, "puts"), nullptr);
    EXPECT_EQ(findSymbol(elf, "puts")->source, pwnelf::SymbolSource::Dynsym);
}

TEST(ElfSymbols, HandlesBinaryWithNoSymbolTables){
    fixture::ElfBuilder b;
    b.add_section({".text", 1, 0x6, 0x401000, {0xc3}, 0, 0, 0});
    const std::vector<std::uint8_t> buf = b.build();
    const pwnelf::ElfFile elf = parse(buf);

    EXPECT_FALSE(elf.has_symtab());
    EXPECT_TRUE(elf.symbols().empty());
    EXPECT_FALSE(elf.has_symbol("main"));
    EXPECT_EQ(elf.find_function("main"), nullptr);
    EXPECT_EQ(elf.function_at(0x401000), nullptr);
}

TEST(ElfSymbols, RejectsSymtabWithInvalidStringTableLink){
    std::vector<std::uint8_t> buf = elfWithSymtab({{"main", 0x401000, 0x20, kGlobalFunc, 1}});
    fixture::patch<std::uint32_t>(buf, shdrOffset(buf, kSymtabIndex) + fixture::kShdrOffLink, 99);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfSymbols, RejectsSymtabLinkedToNonStringTable){
    std::vector<std::uint8_t> buf = elfWithSymtab({{"main", 0x401000, 0x20, kGlobalFunc, 1}});
    fixture::patch<std::uint32_t>(buf, shdrOffset(buf, kSymtabIndex) + fixture::kShdrOffLink, 1);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfSymbols, RejectsSymtabWithZeroEntsize){
    std::vector<std::uint8_t> buf = elfWithSymtab({{"main", 0x401000, 0x20, kGlobalFunc, 1}});
    fixture::patch<std::uint64_t>(buf, shdrOffset(buf, kSymtabIndex) + fixture::kShdrOffEntsize, 0);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfSymbols, RejectsSymtabWithWrongEntsize){
    std::vector<std::uint8_t> buf = elfWithSymtab({{"main", 0x401000, 0x20, kGlobalFunc, 1}});
    fixture::patch<std::uint64_t>(buf, shdrOffset(buf, kSymtabIndex) + fixture::kShdrOffEntsize, 32);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}

TEST(ElfSymbols, RejectsSymbolNameOutsideStringTable){
    std::vector<std::uint8_t> buf = elfWithSymtab({{"main", 0x401000, 0x20, kGlobalFunc, 1}});
    std::uint64_t symtab_off = 0;
    std::memcpy(&symtab_off, buf.data() + shdrOffset(buf, kSymtabIndex) + fixture::kShdrOffOffset,
                sizeof(symtab_off));
    fixture::patch<std::uint32_t>(buf, static_cast<std::size_t>(symtab_off) + fixture::kSymSize
                                       + fixture::kSymOffName, 0xffff);
    EXPECT_THROW(parse(buf), pwnelf::ParseError);
}
