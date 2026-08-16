#include <pwnelf/pattern.hpp>
#include <CLI/CLI.hpp>
#include <iostream>

namespace{
    constexpr int exitOk = 0;
    constexpr int exitAnalysisError = 1;
    constexpr int exitUsageError = 2;
}

int main(int argc, char** argv){
    CLI::App app{"pwnelf - ELF x86-64 analysis"};
    app.require_subcommand(1);

    auto* cyclic_cmd = app.add_subcommand("cyclic", "Generate or look up a deBruijn pattrern");

    std::size_t length = 0;
    std::string lookup;

    auto* len_opt = cyclic_cmd->add_option("length", length, "Number of bytes to generate");
    auto* look_opt = cyclic_cmd->add_option("--lookup", lookup, "Find the offset of value or string");

    len_opt->excludes(look_opt);

    CLI11_PARSE(app, argc, argv);
    try{
        if(*cyclic_cmd){
            if(*look_opt){
                if(lookup.rfind("0x", 0) == 0){
                    std::string digit = lookup.substr(2);
                    std::size_t digit_len = digit.length();
                    if(digit_len % 2 == 1){
                        std::cerr << "error: hex value has an odd number of digits: " << lookup << std::endl;
                        return exitUsageError;
                    }else if(digit_len == 0){
                        std::cerr << "error: hex value has no digits: " << lookup << std::endl;
                        return exitUsageError;
                    }else if(digit.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos){
                        std::cerr << "error: hex value has non hex character: " << lookup << std::endl;
                        return exitUsageError;
                    }else if(digit_len != 8 && digit_len != 16){
                        std::cerr << "error: hex value isn't 4 or 8 bytes: " << lookup << std::endl;
                        return exitUsageError;
                    }

                    std::size_t width = digit_len/2;
                    std::uint64_t value = std::stoull(digit, nullptr, 16);
                    
                    std::optional<std::size_t> res = pwnelf::cyclic_find(value, width);

                    if(res.has_value()){
                        std::cout << *res << std::endl;
                    }else{
                        std::cerr << "error: cannot find pattern: " << lookup << std::endl;
                        return exitAnalysisError;
                    }

                }else{
                    std::optional<std::size_t> res = pwnelf::cyclic_find(lookup);

                    if(res.has_value()){
                        std::cout << *res << std::endl;
                    }else{
                        std::cerr << "error: cannot find pattern: " << lookup << std::endl;
                        return exitAnalysisError;
                    }
                }
            }else{
                if(!(*len_opt)){
                    std::cerr << "error: length not given" << std::endl;
                    return exitUsageError;
                }

                std::string out = pwnelf::cyclic(length);
                std::cout << out << std::endl;
            }
        }
    }catch(const std::exception& e){
        std::cerr << "error: " << e.what() << std::endl;
        return exitUsageError;
    }

    return exitOk;
}
