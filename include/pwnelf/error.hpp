#pragma once

#include <stdexcept>
#include <string>

namespace pwnelf{
    class Error: public std::runtime_error{
        public:
        explicit Error(const std::string& msg) : std::runtime_error(msg){}
    };

    class IoError: public Error{
        public:
        explicit IoError(const std::string& msg) : Error(msg){}
    };

    class ParseError: public Error{
        public:
        explicit ParseError(const std::string& msg) : Error(msg){}
    };

    class UnsupportedError: public Error{
        public:
        explicit UnsupportedError(const std::string& msg) : Error(msg){}
    };
}