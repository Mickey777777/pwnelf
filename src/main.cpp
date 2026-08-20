#include <pwnelf/lookup.hpp>
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

    auto* cyclic_cmd = app.add_subcommand("cyclic", "Generate or look up a de Bruijn pattern");

    std::size_t length = 0;
    std::string lookup;

    auto* len_opt = cyclic_cmd->add_option("length", length, "Number of bytes to generate");
    auto* look_opt = cyclic_cmd->add_option("--lookup", lookup, "Find the offset of value or string");

    len_opt->excludes(look_opt);

    CLI11_PARSE(app, argc, argv);
    try{
        if(*cyclic_cmd){
            if(*look_opt){
                std::optional<std::size_t> res = pwnelf::lookupOffset(lookup);
                if(res.has_value()){
                    std::cout << *res << std::endl;
                }else{
                    std::cerr << "error: cannot find pattern: " << lookup << std::endl;
                    return exitAnalysisError;
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
