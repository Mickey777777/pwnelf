#include <pwnelf/bytes.hpp>
#include <pwnelf/mapped_file.hpp>
#include <pwnelf/elf.hpp>
#include <pwnelf/elf_type.hpp>
#include <pwnelf/hexfmt.hpp>
#include <pwnelf/error.hpp>
#include <pwnelf/reader.hpp>

#include <iostream>
#include <string>
#include <memory>
#include <sstream>
#include <cstdint>
#include <string_view>
#include <vector>
#include <cstddef>
#include <optional>

namespace{
    bool isTableInFile(std::uint64_t offset, std::uint64_t count, std::uint64_t entsize, std::uint64_t fileSize){
        if(count * entsize > fileSize) return false;
        if(offset > fileSize) return false;
        if(count * entsize  > fileSize - offset) return false;
        return true;
    }
}

namespace pwnelf{
    ElfFile::ElfFile(std::unique_ptr<MappedFile> owned, ByteView data, std::string origin)
    : owned_(std::move(owned)), data_(data), reader_(data), origin_(std::move(origin)){
        parse_header();
        parse_segments();
        parse_sections();
        parse_symbols();
        parse_dynamic();
        parse_relocations();
    }

    const ElfHeader& ElfFile::header() const noexcept {return header_;}
    const std::string& ElfFile::origin() const noexcept {return origin_;}
    const Reader& ElfFile::reader() const noexcept {return reader_;}
    ByteView ElfFile::data() const noexcept {return data_;}

    const std::vector<Section>& ElfFile::sections() const noexcept {return sections_;}
    const std::vector<Segment>& ElfFile::segments() const noexcept {return segment_;}
    const std::vector<Symbol>& ElfFile::symbols() const noexcept {return symbols_;}
    bool ElfFile::has_symtab() const noexcept {return has_symtab_;}
    const std::vector<DynamicEntry>& ElfFile::dynamic() const noexcept {return dynamic_;}
    const std::vector<Relocation>& ElfFile::plt_relocations() const noexcept {return relocations_;}

    const char* machine_name(Elf64_Half machine){
        switch (machine) {
            case EM_386:
                return "386";
            case EM_ARM:
                return "ARM";
            case EM_X86_64:
                return "X86_64";
            case EM_AARCH64:
                return "AARCH64";
            case EM_RISCV:
                return "RISCV";
            default:
                return nullptr;
        }
    }

    ElfFile ElfFile::load(const std::string& path){
        std::unique_ptr<MappedFile> owned = std::make_unique<MappedFile>(MappedFile::open(path));
        const ByteView view = owned->view();
        return ElfFile(std::move(owned), view, path);
    }

    ElfFile ElfFile::parse(ByteView data, std::string origin){
        return ElfFile(nullptr, data, std::move(origin));
    }

    void ElfFile::parse_header(){
        const Elf64_Ehdr eh = reader_.read<Elf64_Ehdr>(0, "ELF header");

        // 매직바이트가 틀린경우
        if(!(eh.e_ident[EI_MAG0] == ELFMAG0 &&
        eh.e_ident[EI_MAG1] == ELFMAG1 &&
        eh.e_ident[EI_MAG2] == ELFMAG2 &&
        eh.e_ident[EI_MAG3] == ELFMAG3)){
            std::ostringstream oss;
            oss << origin_ << ": not an ELF file: magic is "
                << hex(eh.e_ident[0], 2) << " " << hex(eh.e_ident[1], 2) << " "
                << hex(eh.e_ident[2], 2) << " " << hex(eh.e_ident[3], 2);
            throw ParseError(oss.str());
        }

        // 64bit가 아닌경우
        if(eh.e_ident[EI_CLASS] != ELFCLASS64){
            std::ostringstream oss;
            oss << origin_ << ": unsupported ELF class "
                << static_cast<int>(eh.e_ident[EI_CLASS])
                << " (pwnelf handles ELFCLASS64 only)";
            throw UnsupportedError(oss.str());
        }

        // 리틀엔디언이 아닌경우
        if(eh.e_ident[EI_DATA] != ELFDATA2LSB){
            std::ostringstream oss;
            oss << origin_ << ": unsupported byte order "
                << static_cast<int>(eh.e_ident[EI_DATA])
                << " (pwnelf handles little-endian only)";
            throw UnsupportedError(oss.str());
        }

        // x86-64가 아닌경우
        if(eh.e_machine != EM_X86_64){
            const char* name = machine_name(eh.e_machine);
            std::ostringstream oss;
            oss << origin_ << ": unsupported machine "
                << (name ? name : "unknown") << " (" << eh.e_machine
                << "); pwnelf handles x86-64 only";
            throw UnsupportedError(oss.str());
        }

        // ehsize가 안맞는경우
        if(eh.e_ehsize != kEhdrSize){
            std::ostringstream oss;
            oss << origin_ << ": e_ehsize is " << eh.e_ehsize
                << ", expected " << kEhdrSize;
            throw ParseError(oss.str());
        }

        // 세그먼트가 있는데 phentsize가 틀린경우
        if(eh.e_phnum > 0 && eh.e_phentsize != kPhdrSize){
            std::ostringstream oss;
            oss << origin_ << ": e_phentsize is " << eh.e_phentsize
                << ", expected " << kPhdrSize;
            throw ParseError(oss.str());
        }

        // 섹션이 있는데 shentsize가 틀린경우
        if(eh.e_shnum > 0 && eh.e_shentsize != kShdrSize){
            std::ostringstream oss;
            oss << origin_ << ": e_shentsize is " << eh.e_shentsize
                << ", expected " << kShdrSize;
            throw ParseError(oss.str());
        }

        // 프로그램 헤더 테이블이 파일 밖인경우
        if(!isTableInFile(eh.e_phoff, eh.e_phnum, eh.e_phentsize, reader_.size())){
            std::ostringstream oss;
            oss << origin_ << ": program header table at " << hex(eh.e_phoff)
                << " (" << eh.e_phnum << " entries) is outside the file";
            throw ParseError(oss.str());
        }

        // 섹션 헤더 테이블이 파일 밖인경우
        if(!isTableInFile(eh.e_shoff, eh.e_shnum, eh.e_shentsize, reader_.size())){
            std::ostringstream oss;
            oss << origin_ << ": section header table at " << hex(eh.e_shoff)
                << " (" << eh.e_shnum << " entries) is outside the file";
            throw ParseError(oss.str());
        }

        if((eh.e_shstrndx != 0) && !(eh.e_shstrndx < eh.e_shnum)){
            std::ostringstream oss;
            oss << origin_ << ": e_shstrndx is " << eh.e_shstrndx
                << ", section count is " << eh.e_shnum;
            throw ParseError(oss.str());
        }

        header_.type = static_cast<ElfType>(eh.e_type);
        header_.machine = eh.e_machine;
        header_.entry = eh.e_entry;
        header_.phoff = eh.e_phoff;
        header_.shoff = eh.e_shoff;
        header_.phentsize = eh.e_phentsize;
        header_.phnum = eh.e_phnum;
        header_.shentsize = eh.e_shentsize;
        header_.shnum = eh.e_shnum;
        header_.shstrndx = eh.e_shstrndx;
    }

    void ElfFile::parse_segments(){
        segment_.reserve(header_.phnum);

        for(size_t i=0; i<header_.phnum; ++i){
            std::uint64_t offset = static_cast<std::uint64_t>(i) * kPhdrSize + header_.phoff;
            Segment s;
            Elf64_Phdr p = reader_.read<Elf64_Phdr>(offset, "program header");
            s.type = p.p_type;
            s.flags = p.p_flags;
            s.offset = p.p_offset;
            s.vaddr = p.p_vaddr;
            s.paddr = p.p_paddr;
            s.filesz = p.p_filesz;
            s.memsz = p.p_memsz;
            s.align = p.p_align;

            if(s.type == PT_LOAD && s.filesz > 0){
                reader_.slice(s.offset, s.filesz, "PT_LOAD segment contents");
            }

            segment_.push_back(s);
        }
    }

    void ElfFile::parse_sections(){
        if(header_.shnum == 0){
            return;
        }

        const std::uint64_t strtab_hdr_off = header_.shoff + static_cast<std::uint64_t>(header_.shstrndx) * kShdrSize;
        const Elf64_Shdr strtab_sh = reader_.read<Elf64_Shdr>(strtab_hdr_off, "section name string table header");

        if(strtab_sh.sh_type == SHT_NOBITS){
            std::ostringstream oss;
            oss << origin_ << ": section name string table is SHT_NOBITS and has no contents";
            throw ParseError(oss.str());
        }

        reader_.slice(strtab_sh.sh_offset, strtab_sh.sh_size, "section name string table");

        const std::uint64_t strtab_off = strtab_sh.sh_offset;
        const std::uint64_t strtab_size = strtab_sh.sh_size;

        for(size_t i=0; i<header_.shnum; ++i){
            std::uint64_t offset = static_cast<std::uint64_t>(i) * kShdrSize + header_.shoff;
            Section sh;
            Elf64_Shdr p = reader_.read<Elf64_Shdr>(offset, "section header");
            if(p.sh_name != 0){
                if(p.sh_name >= strtab_size){
                    std::ostringstream oss;
                    oss << origin_ << ": section " << i << " name offset " << p.sh_name
                        << " is outside the string table (size " << strtab_size << ")";
                    throw ParseError(oss.str());
                }
                sh.name = reader_.cstr(strtab_off + p.sh_name, strtab_size - p.sh_name, "section name");
            }
            sh.type = p.sh_type;
            sh.flags = p.sh_flags;
            sh.addr = p.sh_addr;
            sh.offset = p.sh_offset;
            sh.size = p.sh_size;
            sh.link = p.sh_link;
            sh.info = p.sh_info;
            sh.addralign = p.sh_addralign;
            sh.entsize = p.sh_entsize;
            sh.index = static_cast<std::uint16_t>(i);

            if(sh.type != SHT_NOBITS && sh.size != 0){
                reader_.slice(sh.offset, sh.size, "section contents");
            }

            sections_.push_back(std::move(sh));
        }
    }

    void ElfFile::parse_symbols(){
        for(Section sec : sections_){
            SymbolSource source;
            if(sec.type == SHT_SYMTAB){
                source = SymbolSource::Symtab;
                has_symtab_ = true;
            }else if(sec.type == SHT_DYNSYM){
                source = SymbolSource::Dynsym;
            }else{
                continue;
            }

            if(sec.entsize != sizeof(Elf64_Sym)){
                std::ostringstream oss;
                oss << origin_ << ": symbol table \"" << sec.name << "\" has sh_entsize " << sec.entsize
                    << ", expected " << sizeof(Elf64_Sym);
                throw ParseError(oss.str());
            }

            if(sec.link >= sections_.size()){
                std::ostringstream oss;
                oss << origin_ << ": symbol table \"" << sec.name << "\" links to section " << sec.link
                    << " but the file has " << sections_.size() << " sections";
                throw ParseError(oss.str());
            }

            if(sections_[sec.link].type != SHT_STRTAB){
                std::ostringstream oss;
                oss << origin_ << ": symbol table \"" << sec.name << "\" links to \"" << sections_[sec.link].name
                    << "\" which is not a string table";
                throw ParseError(oss.str());
            }

            const Section& strsec = sections_[sec.link];
            uint64_t count = sec.size / sec.entsize;
            for(uint64_t i=0; i<count; ++i){
                Elf64_Sym raw = reader_.read<Elf64_Sym>(sec.offset + i *sec.entsize, "symbol table entry");
                
                Symbol s;
                s.value = raw.st_value;
                s.size = raw.st_size;
                s.info = raw.st_info;
                s.other = raw.st_other;
                s.shndx = raw.st_shndx;
                s.source = source;

                if(raw.st_name >= strsec.size){
                    std::ostringstream oss;
                    oss << origin_ << ": symbol " << i << " in \"" << sec.name << "\" has name offset " << raw.st_name
                        << " outside \"" << strsec.name << "\" (size " << strsec.size << ")";
                    throw ParseError(oss.str());
                }

                s.name = reader_.cstr(strsec.offset + raw.st_name, strsec.size - raw.st_name, "symbol name");

                symbols_.push_back(std::move(s));
            }
        }
    }

    void ElfFile::parse_dynamic(){
        const Section* dyn = nullptr;
        
        for(const Section& sec : sections_){
            if(sec.type == SHT_DYNAMIC){
                dyn = &sec;
                break;
            }
        }

        if(dyn == nullptr) return;

        if(dyn->entsize != sizeof(Elf64_Dyn)){
            std::ostringstream oss;
            oss << origin_ << ": dynamic section \"" << dyn->name << "\" has sh_entsize " << dyn->entsize
                << ", expected " << sizeof(Elf64_Dyn);
            throw ParseError(oss.str());
        }

        dynamic_link_ = dyn->link;

        std::uint64_t count = dyn->size / dyn->entsize;
        for(std::uint64_t i=0; i<count; ++i){
            Elf64_Dyn raw = reader_.read<Elf64_Dyn>(dyn->offset + i *dyn->entsize, "dynamic entry");
            if(raw.d_tag == DT_NULL) break;

            dynamic_.push_back({raw.d_tag, raw.d_val});
        }
    }

    void ElfFile::parse_relocations(){
        const Section* rela = find_section(".rela.plt");
        if(rela == nullptr) return;

        if(rela->entsize != sizeof(Elf64_Rela)){
            std::ostringstream oss;
            oss << origin_ << ": relocation section \"" << rela->name << "\" has sh_entsize " << rela->entsize
                << ", expected " << sizeof(Elf64_Rela);
            throw ParseError(oss.str());
        }

        const Section* symsec = nullptr;
        if(rela->link != 0){
            if(rela->link >= sections_.size()){
                std::ostringstream oss;
                oss << origin_ << ": relocation section \"" << rela->name << "\" links to section " << rela->link
                    << " but the file has " << sections_.size() << " sections";
                throw ParseError(oss.str());
            }

            symsec = &sections_[rela->link];
            if(symsec->type != SHT_SYMTAB && symsec->type != SHT_DYNSYM){
                std::ostringstream oss;
                oss << origin_ << ": relocation section \"" << rela->name << "\" links to \"" << symsec->name
                    << "\" which is not a symbol table";
                throw ParseError(oss.str());
            }
        }

        std::vector<const Symbol*> linked;

        if(symsec != nullptr){
            SymbolSource want;
            if(symsec->type == SHT_SYMTAB){
                want = SymbolSource::Symtab;
            }else{
                want = SymbolSource::Dynsym;
            }

            for(const Symbol& s : symbols_){
                if(s.source == want){
                    linked.push_back(&s);
                }
            }
        }

        std::uint64_t count = rela->size / rela->entsize;

        for(uint64_t i=0; i<count; ++i){
            Elf64_Rela raw = reader_.read<Elf64_Rela>(rela->offset + i *rela->entsize, "relocation entry");

            Relocation rel;
            rel.offset = raw.r_offset;
            rel.type = raw.r_info & 0xffffffff;
            rel.sym_index = raw.r_info >> 32;
            rel.addend = raw.r_addend;

            if(rel.sym_index != 0){
                if(rel.sym_index >= linked.size()){
                    std::ostringstream oss;
                    oss << origin_ << ": relocation " << i << " in \"" << rela->name << "\" references symbol "
                        << rel.sym_index << " but the linked table has " << linked.size() << " symbols";
                    throw ParseError(oss.str());
                }

                rel.symbol_name = linked[rel.sym_index]->name;
            }

            relocations_.push_back(std::move(rel));
        }
    }

    const Section* ElfFile::find_section(std::string_view name) const noexcept{
        for(size_t i=0; i<sections_.size(); ++i){
            if(sections_[i].name == name){
                return &sections_[i];
            }
        }
        return nullptr;
    }



    ByteView ElfFile::section_data(const Section& s) const {
        if(s.type == SHT_NOBITS || s.size == 0){
            return ByteView();
        }

        return reader_.slice(s.offset, s.size, "section contents");
    }

    std::optional<std::uint64_t> ElfFile::vaddr_to_offset(std::uint64_t vaddr) const noexcept{
        for(const Segment& s : segment_){
            if(s.type != PT_LOAD){
                continue;
            }
            if(vaddr < s.vaddr){
                continue;
            }

            const std::uint64_t d = vaddr - s.vaddr;
            if(d < s.filesz){
                return s.offset + d;
            }
        }

        return std::nullopt;
    }

    std::vector<const Segment*> ElfFile::executable_segments() const {
        std::vector<const Segment*> ret;

        for(const Segment& s : segment_){
            if(s.type == PT_LOAD && (s.flags & PF_X) != 0){
                ret.push_back(&s);
            }
        }

        return ret;
    }

    unsigned char Symbol::type() const noexcept {
        return info & 0x0f;
    }

    unsigned char Symbol::bind() const noexcept {
        return info >> 4;
    }

    bool Symbol::is_defined() const noexcept {
        if(shndx==SHN_UNDEF) return false;
        return true;
    }

    bool Symbol::is_function() const noexcept {
        if(type() == STT_FUNC && is_defined() && size > 0) return true;
        return false;
    }

    bool ElfFile::has_symbol(std::string_view name) const noexcept {
        for(const Symbol& s : symbols_){
            if(s.name == name) return true;
        }

        return false;
    }

    const Symbol* ElfFile::find_function(std::string_view name) const noexcept {
        for(const Symbol& s : symbols_){
            if(s.is_function() && s.name == name) return &s;
        }

        return nullptr;
    }

    const Symbol* ElfFile::function_at(std::uint64_t addr) const noexcept {
        for(const Symbol& s : symbols_){
            if(!s.is_function()){
                continue;
            }
            if(addr < s.value){
                continue;
            }

            const std::uint64_t d = addr - s.value;
            if(d < s.size){
                return &s;
            }
        }

        return nullptr;
    }

    bool ElfFile::has_dynamic_tag(std::int64_t tag) const noexcept {
        for(const DynamicEntry& de : dynamic_){
            if(tag == de.tag){
                return true;
            }
        }

        return false;
    }

    std::optional<std::uint64_t> ElfFile::dynamic_value(std::int64_t tag) const noexcept {
        for(const DynamicEntry& de : dynamic_){
            if(de.tag == tag){
                return de.value;
            }
        }

        return std::nullopt;
    }

    std::optional<std::string> ElfFile::dynamic_string(std::int64_t tag) const {
        const std::optional<std::uint64_t> off = dynamic_value(tag);
        if(!off){
            return std::nullopt;
        }

        if(dynamic_link_ >= sections_.size()){
            std::ostringstream oss;
            oss << origin_ << ": dynamic section links to section " << dynamic_link_
                << " but the file has " << sections_.size() << " sections";
            throw ParseError(oss.str());
        }

        const Section& strsec = sections_[dynamic_link_];
        if(strsec.type != SHT_STRTAB){
            std::ostringstream oss;
            oss << origin_ << ": dynamic section links to \"" << strsec.name
                << "\" which is not a string table";
            throw ParseError(oss.str());
        }

        if(*off >= strsec.size){
            std::ostringstream oss;
            oss << origin_ << ": dynamic string offset " << *off << " is outside \"" << strsec.name
                << "\" (size " << strsec.size << ")";
            throw ParseError(oss.str());
        }

        return reader_.cstr(strsec.offset + *off, strsec.size - *off, "dynamic string");
    }

    std::optional<std::string> ElfFile::got_symbol(std::uint64_t got_addr) const noexcept {
        for(const Relocation& r : relocations_){
            if(r.offset == got_addr && !r.symbol_name.empty()){
                return r.symbol_name;
            }
        }

        return std::nullopt;
    }
}