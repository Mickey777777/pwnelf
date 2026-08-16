#include <gtest/gtest.h>
#include <pwnelf/lookup.hpp>
#include <pwnelf/pattern.hpp>

#include <optional>
#include <stdexcept>
#include <string>

TEST(Lookup, FindsStringOffset) {
    EXPECT_EQ(pwnelf::lookupOffset("aaaa"), std::optional<std::size_t>{0});
    EXPECT_EQ(pwnelf::lookupOffset("baaa"), std::optional<std::size_t>{4});
    EXPECT_EQ(pwnelf::lookupOffset("caaa"), std::optional<std::size_t>{8});
}

TEST(Lookup, FindsHexOffset) {
    EXPECT_EQ(pwnelf::lookupOffset("0x61616161"), std::optional<std::size_t>{0});
    EXPECT_EQ(pwnelf::lookupOffset("0x61616162"), std::optional<std::size_t>{4});
    EXPECT_EQ(pwnelf::lookupOffset("0x61616163"), std::optional<std::size_t>{8});
}

TEST(Lookup, FindsEightByteHexOffset) {
    EXPECT_EQ(pwnelf::lookupOffset("0x6161616261616161"), std::optional<std::size_t>{0});
    EXPECT_EQ(pwnelf::lookupOffset("0x6161616361616162"), std::optional<std::size_t>{4});
}

TEST(Lookup, UsesEveryByteOfAnEightByteValue) {
    EXPECT_FALSE(pwnelf::lookupOffset("0x7a7a7a7a61616161").has_value());
    EXPECT_FALSE(pwnelf::lookupOffset("0x7a7a7a7a61616162").has_value());
}

TEST(Lookup, AcceptsUppercaseHexDigits) {
    EXPECT_EQ(pwnelf::lookupOffset("0x6161616A"), pwnelf::lookupOffset("0x6161616a"));
    EXPECT_TRUE(pwnelf::lookupOffset("0x6161616A").has_value());
}

TEST(Lookup, StringAndHexAgree) {
    EXPECT_EQ(pwnelf::lookupOffset("baaa"), pwnelf::lookupOffset("0x61616162"));
    EXPECT_EQ(pwnelf::lookupOffset("caaa"), pwnelf::lookupOffset("0x61616163"));
}

TEST(Lookup, ReturnsNulloptWhenPatternDoesNotContainValue) {
    EXPECT_FALSE(pwnelf::lookupOffset("ZZZZ").has_value());
    EXPECT_FALSE(pwnelf::lookupOffset("").has_value());
    EXPECT_FALSE(pwnelf::lookupOffset("0x00000000").has_value());
    EXPECT_FALSE(pwnelf::lookupOffset("0xffffffff").has_value());
}

TEST(Lookup, ThrowsOnOddDigitCount) {
    EXPECT_THROW(pwnelf::lookupOffset("0xabc"), std::invalid_argument);
    EXPECT_THROW(pwnelf::lookupOffset("0x616161612"), std::invalid_argument);
}

TEST(Lookup, ThrowsWhenHexHasNoDigits) {
    EXPECT_THROW(pwnelf::lookupOffset("0x"), std::invalid_argument);
}

TEST(Lookup, ThrowsOnNonHexCharacter) {
    EXPECT_THROW(pwnelf::lookupOffset("0xzzzzzzzz"), std::invalid_argument);
    EXPECT_THROW(pwnelf::lookupOffset("0x6161616g"), std::invalid_argument);
    EXPECT_THROW(pwnelf::lookupOffset("0x61 61616"), std::invalid_argument);
}

TEST(Lookup, ThrowsWhenWidthIsNotFourOrEightBytes) {
    EXPECT_THROW(pwnelf::lookupOffset("0x6162"), std::invalid_argument);
    EXPECT_THROW(pwnelf::lookupOffset("0x616161"), std::invalid_argument);
    EXPECT_THROW(pwnelf::lookupOffset("0x616161626161616261"), std::invalid_argument);
}

TEST(Lookup, ErrorMessageNamesTheProblemAndTheInput) {
    try {
        pwnelf::lookupOffset("0xabc");
        FAIL() << "expected std::invalid_argument";
    } catch (const std::invalid_argument& e) {
        const std::string msg = e.what();
        EXPECT_NE(msg.find("odd number"), std::string::npos) << msg;
        EXPECT_NE(msg.find("0xabc"), std::string::npos) << msg;
    }
}

TEST(Lookup, TreatsInputWithoutPrefixAsLiteralString) {
    EXPECT_FALSE(pwnelf::lookupOffset("61616162").has_value());
    EXPECT_FALSE(pwnelf::lookupOffset("0X61616162").has_value());
}

TEST(Lookup, RoundTripsEveryOffset) {
    const std::string s = pwnelf::cyclic(2000);
    for (std::size_t i = 0; i + 4 <= s.size(); ++i) {
        const auto r = pwnelf::lookupOffset(s.substr(i, 4));
        ASSERT_TRUE(r.has_value()) << "not found at offset " << i;
        EXPECT_EQ(*r, i);
    }
}
