#pragma once

#include <cstddef>
#include <optional>
#include <string>

namespace pwnelf{
    std::optional<std::size_t> lookupOffset(std::string arg);
}