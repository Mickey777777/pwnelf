#include <pwnelf/bytes.hpp>
#include <pwnelf/mapped_file.hpp>
#include <pwnelf/elf.hpp>
#include <pwnelf/elf_type.hpp>
#include <pwnelf/hexfmt.hpp>
#include <pwnelf/error.hpp>

#include <string>
#include <memory>
#include <sstream>
#include <cstdint>

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
    }

    const ElfHeader& ElfFile::header() const noexcept {return header_;}
    const std::string& ElfFile::origin() const noexcept {return origin_;}
    const Reader& ElfFile::reader() const noexcept {return reader_;}
    ByteView ElfFile::data() const noexcept {return data_;}

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
}