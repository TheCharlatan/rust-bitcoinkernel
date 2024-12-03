// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/string.h>

#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>

using namespace util;

BOOST_AUTO_TEST_SUITE(util_string_tests)

// Helper to allow compile-time sanity checks while providing the number of
// args directly. Normally PassFmt<sizeof...(Args)> would be used.
template <unsigned NumArgs>
inline void PassFmt(util::ConstevalFormatString<NumArgs> fmt)
{
    // This was already executed at compile-time, but is executed again at run-time to avoid -Wunused.
    decltype(fmt)::Detail_CheckNumFormatSpecifiers(fmt.fmt);
}
template <unsigned WrongNumArgs>
inline void FailFmtWithError(const char* wrong_fmt, std::string_view error)
{
    BOOST_CHECK_EXCEPTION(util::ConstevalFormatString<WrongNumArgs>::Detail_CheckNumFormatSpecifiers(wrong_fmt), const char*, HasReason(error));
}

BOOST_AUTO_TEST_CASE(ConstevalFormatString_NumSpec)
{
    PassFmt<0>("");
    PassFmt<0>("%%");
    PassFmt<1>("%s");
    PassFmt<0>("%%s");
    PassFmt<0>("s%%");
    PassFmt<1>("%%%s");
    PassFmt<1>("%s%%");
    PassFmt<0>(" 1$s");
    PassFmt<1>("%1$s");
    PassFmt<1>("%1$s%1$s");
    PassFmt<2>("%2$s");
    PassFmt<2>("%2$s 4$s %2$s");
    PassFmt<129>("%129$s 999$s %2$s");
    PassFmt<1>("%02d");
    PassFmt<1>("%+2s");
    PassFmt<1>("%.6i");
    PassFmt<1>("%5.2f");
    PassFmt<1>("%5.f");
    PassFmt<1>("%.f");
    PassFmt<1>("%#x");
    PassFmt<1>("%1$5i");
    PassFmt<1>("%1$-5i");
    PassFmt<1>("%1$.5i");
    // tinyformat accepts almost any "type" spec, even '%', or '_', or '\n'.
    PassFmt<1>("%123%");
    PassFmt<1>("%123%s");
    PassFmt<1>("%_");
    PassFmt<1>("%\n");

    PassFmt<2>("%*c");
    PassFmt<2>("%+*c");
    PassFmt<2>("%.*f");
    PassFmt<3>("%*.*f");
    PassFmt<3>("%2$*3$d");
    PassFmt<3>("%2$*3$.9d");
    PassFmt<3>("%2$.*3$d");
    PassFmt<3>("%2$9.*3$d");
    PassFmt<3>("%2$+9.*3$d");
    PassFmt<4>("%3$*2$.*4$f");

    // Make sure multiple flag characters "- 0+" are accepted
    PassFmt<3>("'%- 0+*.*f'");
    PassFmt<3>("'%1$- 0+*3$.*2$f'");

    auto err_mix{"Format specifiers must be all positional or all non-positional!"};
    FailFmtWithError<1>("%s%1$s", err_mix);
    FailFmtWithError<2>("%2$*d", err_mix);
    FailFmtWithError<2>("%*2$d", err_mix);
    FailFmtWithError<2>("%.*3$d", err_mix);
    FailFmtWithError<2>("%2$.*d", err_mix);

    auto err_num{"Format specifier count must match the argument count!"};
    FailFmtWithError<1>("", err_num);
    FailFmtWithError<0>("%s", err_num);
    FailFmtWithError<2>("%s", err_num);
    FailFmtWithError<0>("%1$s", err_num);
    FailFmtWithError<2>("%1$s", err_num);
    FailFmtWithError<1>("%*c", err_num);

    auto err_0_pos{"Positional format specifier must have position of at least 1"};
    FailFmtWithError<1>("%$s", err_0_pos);
    FailFmtWithError<1>("%$", err_0_pos);
    FailFmtWithError<0>("%0$", err_0_pos);
    FailFmtWithError<0>("%0$s", err_0_pos);
    FailFmtWithError<2>("%2$*$d", err_0_pos);
    FailFmtWithError<2>("%2$*0$d", err_0_pos);
    FailFmtWithError<3>("%3$*2$.*$f", err_0_pos);
    FailFmtWithError<3>("%3$*2$.*0$f", err_0_pos);

    auto err_term{"Format specifier incorrectly terminated by end of string"};
    FailFmtWithError<1>("%", err_term);
    FailFmtWithError<1>("%9", err_term);
    FailFmtWithError<1>("%9.", err_term);
    FailFmtWithError<1>("%9.9", err_term);
    FailFmtWithError<1>("%*", err_term);
    FailFmtWithError<1>("%+*", err_term);
    FailFmtWithError<1>("%.*", err_term);
    FailFmtWithError<1>("%9.*", err_term);
    FailFmtWithError<1>("%1$", err_term);
    FailFmtWithError<1>("%1$9", err_term);
    FailFmtWithError<2>("%1$*2$", err_term);
    FailFmtWithError<2>("%1$.*2$", err_term);
    FailFmtWithError<2>("%1$9.*2$", err_term);
}

BOOST_AUTO_TEST_SUITE_END()
