#include "elf_fixture.hpp"

#include <fstream>
#include <utility>

namespace{
    void append_u32(std::vector<std::uint8_t>& v, std::uint32_t x){
        for(int i = 0; i < 4; ++i) v.push_back(static_cast<std::uint8_t>((x >> (8 * i)) & 0xff));
    }

    void append_u64(std::vector<std::uint8_t>& v, std::uint64_t x){
        for(int i = 0; i < 8; ++i) v.push_back(static_cast<std::uint8_t>((x >> (8 * i)) & 0xff));
    }

    void pad_to(std::vector<std::uint8_t>& v, std::size_t align){
        while(v.size() % align != 0) v.push_back(0);
    }
}

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

    ElfBuilder& ElfBuilder::set_type(std::uint16_t type){ type_ = type; return *this; }
    ElfBuilder& ElfBuilder::set_entry(std::uint64_t entry){ entry_ = entry; return *this; }
    ElfBuilder& ElfBuilder::add_section(SectionSpec spec){ sections_.push_back(std::move(spec)); return *this; }
    ElfBuilder& ElfBuilder::add_segment(SegmentSpec spec){ segments_.push_back(std::move(spec)); return *this; }

    std::vector<std::uint8_t> ElfBuilder::build() const {
        std::vector<std::uint8_t> shstrtab{0};
        std::vector<std::uint32_t> name_offsets;
        for(const SectionSpec& s : sections_){
            name_offsets.push_back(static_cast<std::uint32_t>(shstrtab.size()));
            shstrtab.insert(shstrtab.end(), s.name.begin(), s.name.end());
            shstrtab.push_back(0);
        }
        const std::uint32_t shstrtab_name_off = static_cast<std::uint32_t>(shstrtab.size());
        const std::string shstrtab_name = ".shstrtab";
        shstrtab.insert(shstrtab.end(), shstrtab_name.begin(), shstrtab_name.end());
        shstrtab.push_back(0);

        std::vector<std::uint8_t> out(kEhdrSize, 0);

        const std::uint64_t phoff = segments_.empty() ? 0 : out.size();
        for(const SegmentSpec& p : segments_){
            append_u32(out, p.type);
            append_u32(out, p.flags);
            append_u64(out, p.offset);
            append_u64(out, p.vaddr);
            append_u64(out, p.vaddr);
            append_u64(out, p.filesz);
            append_u64(out, p.memsz ? p.memsz : p.filesz);
            append_u64(out, p.align);
        }

        std::vector<std::uint64_t> data_offsets;
        for(const SectionSpec& s : sections_){
            pad_to(out, 16);
            data_offsets.push_back(out.size());
            out.insert(out.end(), s.data.begin(), s.data.end());
        }

        pad_to(out, 16);
        const std::uint64_t shstrtab_offset = out.size();
        out.insert(out.end(), shstrtab.begin(), shstrtab.end());

        for(const SegmentSpec& p : segments_){
            const std::size_t end = static_cast<std::size_t>(p.offset + p.filesz);
            if(out.size() < end) out.resize(end, 0);
        }

        pad_to(out, 8);
        const std::uint64_t shoff = out.size();
        out.insert(out.end(), kShdrSize, 0);

        for(std::size_t i = 0; i < sections_.size(); ++i){
            const SectionSpec& s = sections_[i];
            append_u32(out, name_offsets[i]);
            append_u32(out, s.type);
            append_u64(out, s.flags);
            append_u64(out, s.addr);
            append_u64(out, data_offsets[i]);
            append_u64(out, s.data.size());
            append_u32(out, s.link);
            append_u32(out, s.info);
            append_u64(out, 1);
            append_u64(out, s.entsize);
        }

        append_u32(out, shstrtab_name_off);
        append_u32(out, 3);
        append_u64(out, 0);
        append_u64(out, 0);
        append_u64(out, shstrtab_offset);
        append_u64(out, shstrtab.size());
        append_u32(out, 0);
        append_u32(out, 0);
        append_u64(out, 1);
        append_u64(out, 0);

        const std::uint16_t shnum = static_cast<std::uint16_t>(sections_.size() + 2);
        const std::uint16_t shstrndx = static_cast<std::uint16_t>(sections_.size() + 1);

        std::vector<std::uint8_t> ehdr = elf64_header_only();
        patch<std::uint16_t>(ehdr, kEhdrOffType, type_);
        patch<std::uint64_t>(ehdr, kEhdrOffEntry, entry_);
        patch<std::uint64_t>(ehdr, kEhdrOffPhoff, phoff);
        patch<std::uint64_t>(ehdr, kEhdrOffShoff, shoff);
        patch<std::uint16_t>(ehdr, kEhdrOffPhnum, static_cast<std::uint16_t>(segments_.size()));
        patch<std::uint16_t>(ehdr, kEhdrOffShnum, shnum);
        patch<std::uint16_t>(ehdr, kEhdrOffShstrndx, shstrndx);
        std::memcpy(out.data(), ehdr.data(), kEhdrSize);

        return out;
    }
}
