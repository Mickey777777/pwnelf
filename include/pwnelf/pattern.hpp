#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace pwnelf {

std::string cyclic(std::size_t len);
std::optional<std::size_t> cyclic_find(std::string query);
std::optional<std::size_t> cyclic_find(std::uint64_t value, std::size_t width);

}  // namespace pwnelf
