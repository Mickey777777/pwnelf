#include <gtest/gtest.h>
#include <pwnelf/pattern.hpp>

#include <cstdint>
#include <set>
#include <stdexcept>
#include <string>

TEST(Pattern, MatchesPwntoolsPrefix) {
    EXPECT_EQ(pwnelf::cyclic(21), "aaaabaaacaaadaaaeaaaf");
}

TEST(Pattern, ThrowsWhenLengthExceedsMaximum) {
    EXPECT_THROW(pwnelf::cyclic(456977), std::length_error);
    EXPECT_NO_THROW(pwnelf::cyclic(456976));
}

TEST(Pattern, AllSubsequencesAreUnique) {
    const std::string s = pwnelf::cyclic(5000);
    std::set<std::string> seen;
    for (std::size_t i = 0; i + 4 <= s.size(); ++i) {
        const std::string sub = s.substr(i, 4);
        EXPECT_TRUE(seen.insert(sub).second)
            << "duplicate \"" << sub << "\" at offset " << i;
    }
}

TEST(Pattern, ReturnsExactLength) {
    EXPECT_EQ(pwnelf::cyclic(0).size(), 0u);
    EXPECT_EQ(pwnelf::cyclic(1), "a");
    EXPECT_EQ(pwnelf::cyclic(200).size(), 200u);
    EXPECT_EQ(pwnelf::cyclic(456976).size(), 456976u);
}

TEST(Pattern, ShorterLengthIsPrefixOfLonger) {
    const std::string longer = pwnelf::cyclic(500);
    EXPECT_EQ(pwnelf::cyclic(21), longer.substr(0, 21));
    EXPECT_EQ(pwnelf::cyclic(100), longer.substr(0, 100));
}

TEST(PatternFind, FindsOffsetOfSubstring) {
    auto a = pwnelf::cyclic_find("aaaa");
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(*a, 0u);

    auto b = pwnelf::cyclic_find("baaa");
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(*b, 4u);

    auto c = pwnelf::cyclic_find("caaa");
    ASSERT_TRUE(c.has_value());
    EXPECT_EQ(*c, 8u);
}

TEST(PatternFind, ReturnsNulloptWhenNotFound) {
    EXPECT_FALSE(pwnelf::cyclic_find("ZZZZ").has_value());
    EXPECT_FALSE(pwnelf::cyclic_find("").has_value());
    EXPECT_FALSE(pwnelf::cyclic_find("aa aa").has_value());
}

TEST(PatternFind, ReadsValueAsLittleEndian) {
    auto zero = pwnelf::cyclic_find(std::uint64_t{0x61616161}, 4);
    ASSERT_TRUE(zero.has_value());
    EXPECT_EQ(*zero, 0u);

    auto four = pwnelf::cyclic_find(std::uint64_t{0x61616162}, 4);
    ASSERT_TRUE(four.has_value());
    EXPECT_EQ(*four, 4u);

    auto eight = pwnelf::cyclic_find(std::uint64_t{0x61616163}, 4);
    ASSERT_TRUE(eight.has_value());
    EXPECT_EQ(*eight, 8u);
}

TEST(PatternFind, AcceptsIntegerLiteralWithoutCast) {
    auto r = pwnelf::cyclic_find(0x61616162, 4);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, 4u);
}

// "aaaabaaa" = 61 61 61 61 62 61 61 61 -> 리틀엔디언 u64 0x6161616261616161
// "baaacaaa" = 62 61 61 61 63 61 61 61 -> 0x6161616361616162
TEST(PatternFind, HandlesEightByteValues) {
    auto zero = pwnelf::cyclic_find(std::uint64_t{0x6161616261616161}, 8);
    ASSERT_TRUE(zero.has_value());
    EXPECT_EQ(*zero, 0u);

    auto four = pwnelf::cyclic_find(std::uint64_t{0x6161616361616162}, 8);
    ASSERT_TRUE(four.has_value());
    EXPECT_EQ(*four, 4u);
}

TEST(PatternFind, ValueAndStringLookupAgree) {
    const std::string s = pwnelf::cyclic(100);
    for (std::size_t i = 0; i + 4 <= s.size(); ++i) {
        const std::string sub = s.substr(i, 4);
        std::uint64_t value = 0;
        for (std::size_t b = 0; b < 4; ++b) {
            value |= static_cast<std::uint64_t>(static_cast<unsigned char>(sub[b])) << (8 * b);
        }
        EXPECT_EQ(pwnelf::cyclic_find(sub), pwnelf::cyclic_find(value, 4))
            << "mismatch at offset " << i << " for \"" << sub << "\"";
    }
}

TEST(PatternFind, RoundTripsEveryOffset) {
    const std::string s = pwnelf::cyclic(5000);
    for (std::size_t i = 0; i + 4 <= s.size(); ++i) {
        auto r = pwnelf::cyclic_find(s.substr(i, 4));
        ASSERT_TRUE(r.has_value()) << "not found at offset " << i;
        EXPECT_EQ(*r, i) << "wrong offset for \"" << s.substr(i, 4) << "\"";
    }
}
