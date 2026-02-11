/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2014 Andrew Gaul <andrew@gaul.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <cstdlib>
#include <string>

#include "s3fs_logger.h"
#include "string_util.h"
#include "test_util.h"

using namespace std::string_literals;

//-------------------------------------------------------------------
// Global variables for test_string_util
//-------------------------------------------------------------------
bool foreground                   = false;
std::string instance_name;

void test_trim()
{
    ASSERT_EQUALS("1234"s, trim("  1234  "));
    ASSERT_EQUALS("1234"s, trim("1234  "));
    ASSERT_EQUALS("1234"s, trim("  1234"));
    ASSERT_EQUALS("1234"s, trim("1234"));

    ASSERT_EQUALS("1234  "s, trim_left("  1234  "));
    ASSERT_EQUALS("1234  "s, trim_left("1234  "));
    ASSERT_EQUALS("1234"s, trim_left("  1234"));
    ASSERT_EQUALS("1234"s, trim_left("1234"));

    ASSERT_EQUALS("  1234"s, trim_right("  1234  "));
    ASSERT_EQUALS("1234"s, trim_right("1234  "));
    ASSERT_EQUALS("  1234"s, trim_right("  1234"));
    ASSERT_EQUALS("1234"s, trim_right("1234"));

    ASSERT_EQUALS("1234"s, peeloff("\"1234\""));            // "1234"   -> 1234
    ASSERT_EQUALS("\"1234\""s, peeloff("\"\"1234\"\""));    // ""1234"" -> "1234"
    ASSERT_EQUALS("\"1234"s, peeloff("\"\"1234\""));        // ""1234"  ->  "1234
    ASSERT_EQUALS("1234\""s, peeloff("\"1234\"\""));        // "1234""  -> 1234"
    ASSERT_EQUALS("\"1234"s, peeloff("\"1234"));            // "1234    -> "1234
    ASSERT_EQUALS("1234\""s, peeloff("1234\""));            // 1234"    -> 1234"
    ASSERT_EQUALS(" \"1234\""s, peeloff(" \"1234\""));      // _"1234"  -> _"1234"
    ASSERT_EQUALS("\"1234\" "s, peeloff("\"1234\" "));      // "1234"_  -> "1234"_
}

void test_base64()
{
    std::string buf;
    char tmpbuf = '\0';

    ASSERT_EQUALS(s3fs_base64(nullptr, 0), ""s);
    buf = s3fs_decode64(nullptr, 0);
    ASSERT_BUFEQUALS(buf.c_str(), buf.length(), &tmpbuf, 0);

    ASSERT_EQUALS(s3fs_base64(reinterpret_cast<const unsigned char *>(""), 0), ""s);
    buf = s3fs_decode64("", 0);
    ASSERT_BUFEQUALS(buf.c_str(), buf.length(), &tmpbuf, 0);

    ASSERT_EQUALS(s3fs_base64(reinterpret_cast<const unsigned char *>("1"), 1), "MQ=="s);
    buf = s3fs_decode64("MQ==", 4);
    ASSERT_BUFEQUALS(buf.c_str(), buf.length(), "1", 1);
    ASSERT_EQUALS(buf.length(), static_cast<size_t>(1));

    ASSERT_EQUALS(s3fs_base64(reinterpret_cast<const unsigned char *>("12"), 2), "MTI="s);
    buf = s3fs_decode64("MTI=", 4);
    ASSERT_BUFEQUALS(buf.c_str(), buf.length(), "12", 2);
    ASSERT_EQUALS(buf.length(), static_cast<size_t>(2));

    ASSERT_EQUALS(s3fs_base64(reinterpret_cast<const unsigned char *>("123"), 3), "MTIz"s);
    buf = s3fs_decode64("MTIz", 4);
    ASSERT_BUFEQUALS(buf.c_str(), buf.length(), "123", 3);
    ASSERT_EQUALS(buf.length(), static_cast<size_t>(3));

    ASSERT_EQUALS(s3fs_base64(reinterpret_cast<const unsigned char *>("1234"), 4), "MTIzNA=="s);
    buf = s3fs_decode64("MTIzNA==", 8);
    ASSERT_BUFEQUALS(buf.c_str(), buf.length(), "1234", 4);
    ASSERT_EQUALS(buf.length(), static_cast<size_t>(4));

    // TODO: invalid input
}

void test_strtoofft()
{
    off_t value;

    ASSERT_TRUE(s3fs_strtoofft(&value, "0"));
    ASSERT_EQUALS(value, static_cast<off_t>(0L));

    ASSERT_TRUE(s3fs_strtoofft(&value, "9"));
    ASSERT_EQUALS(value, static_cast<off_t>(9L));

    ASSERT_FALSE(s3fs_strtoofft(&value, "A"));

    ASSERT_TRUE(s3fs_strtoofft(&value, "A", /*base=*/ 16));
    ASSERT_EQUALS(value, static_cast<off_t>(10L));

    ASSERT_TRUE(s3fs_strtoofft(&value, "F", /*base=*/ 16));
    ASSERT_EQUALS(value, static_cast<off_t>(15L));

    ASSERT_TRUE(s3fs_strtoofft(&value, "a", /*base=*/ 16));
    ASSERT_EQUALS(value, static_cast<off_t>(10L));

    ASSERT_TRUE(s3fs_strtoofft(&value, "f", /*base=*/ 16));
    ASSERT_EQUALS(value, static_cast<off_t>(15L));

    ASSERT_TRUE(s3fs_strtoofft(&value, "deadbeef", /*base=*/ 16));
    ASSERT_EQUALS(value, static_cast<off_t>(3'735'928'559L));
}

void test_wtf8_encoding()
{
    auto ascii = "normal std::string"s;
    auto utf8 = "Hyld\xc3\xbdpi \xc3\xbej\xc3\xb3\xc3\xb0""f\xc3\xa9lagsins vex \xc3\xbar k\xc3\xa6rkomnu b\xc3\xb6li \xc3\xad \xc3\xa1st"s;
    auto cp1252 = "Hyld\xfdpi \xfej\xf3\xf0""f\xe9lagsins vex \xfar k\xe6rkomnu b\xf6li \xed \xe1st"s;
    std::string broken = utf8;  // NOLINT(bugprone-exception-escape)
    broken[14] = '\x97';
    std::string mixed = ascii + utf8 + cp1252;

    ASSERT_EQUALS(s3fs_wtf8_encode(ascii), ascii);
    ASSERT_EQUALS(s3fs_wtf8_decode(ascii), ascii);
    ASSERT_EQUALS(s3fs_wtf8_encode(utf8), utf8);
    ASSERT_EQUALS(s3fs_wtf8_decode(utf8), utf8);

    ASSERT_NEQUALS(s3fs_wtf8_encode(cp1252), cp1252);
    ASSERT_EQUALS(s3fs_wtf8_decode(s3fs_wtf8_encode(cp1252)), cp1252);

    ASSERT_NEQUALS(s3fs_wtf8_encode(broken), broken);
    ASSERT_EQUALS(s3fs_wtf8_decode(s3fs_wtf8_encode(broken)), broken);

    ASSERT_NEQUALS(s3fs_wtf8_encode(mixed), mixed);
    ASSERT_EQUALS(s3fs_wtf8_decode(s3fs_wtf8_encode(mixed)), mixed);
}

void test_cr_encoding()
{
    // bse strings
    auto base_no = "STR"s;

    auto base_end_cr1 = "STR\r"s;
    auto base_mid_cr1 = "STR\rSTR"s;
    auto base_end_cr2 = "STR\r\r"s;
    auto base_mid_cr2 = "STR\r\rSTR"s;

    auto base_end_per1 = "STR%"s;
    auto base_mid_per1 = "STR%STR"s;
    auto base_end_per2 = "STR%%"s;
    auto base_mid_per2 = "STR%%STR"s;

    auto base_end_crlf1 = "STR\r\n"s;
    auto base_mid_crlf1 = "STR\r\nSTR"s;
    auto base_end_crlf2 = "STR\r\n\r\n"s;
    auto base_mid_crlf2 = "STR\r\n\r\nSTR"s;

    auto base_end_crper1 = "STR%\r"s;
    auto base_mid_crper1 = "STR%\rSTR"s;
    auto base_end_crper2 = "STR%\r%\r"s;
    auto base_mid_crper2 = "STR%\r%\rSTR"s;

    // encode->decode->compare
    ASSERT_EQUALS(get_decoded_cr_code(get_encoded_cr_code(base_no.c_str()).c_str()),         base_no);

    ASSERT_EQUALS(get_decoded_cr_code(get_encoded_cr_code(base_end_cr1.c_str()).c_str()),    base_end_cr1);
    ASSERT_EQUALS(get_decoded_cr_code(get_encoded_cr_code(base_mid_cr1.c_str()).c_str()),    base_mid_cr1);
    ASSERT_EQUALS(get_decoded_cr_code(get_encoded_cr_code(base_end_cr2.c_str()).c_str()),    base_end_cr2);
    ASSERT_EQUALS(get_decoded_cr_code(get_encoded_cr_code(base_mid_cr2.c_str()).c_str()),    base_mid_cr2);

    ASSERT_EQUALS(get_decoded_cr_code(get_encoded_cr_code(base_end_per1.c_str()).c_str()),   base_end_per1);
    ASSERT_EQUALS(get_decoded_cr_code(get_encoded_cr_code(base_mid_per1.c_str()).c_str()),   base_mid_per1);
    ASSERT_EQUALS(get_decoded_cr_code(get_encoded_cr_code(base_end_per2.c_str()).c_str()),   base_end_per2);
    ASSERT_EQUALS(get_decoded_cr_code(get_encoded_cr_code(base_mid_per2.c_str()).c_str()),   base_mid_per2);

    ASSERT_EQUALS(get_decoded_cr_code(get_encoded_cr_code(base_end_crlf1.c_str()).c_str()),  base_end_crlf1);
    ASSERT_EQUALS(get_decoded_cr_code(get_encoded_cr_code(base_mid_crlf1.c_str()).c_str()),  base_mid_crlf1);
    ASSERT_EQUALS(get_decoded_cr_code(get_encoded_cr_code(base_end_crlf2.c_str()).c_str()),  base_end_crlf2);
    ASSERT_EQUALS(get_decoded_cr_code(get_encoded_cr_code(base_mid_crlf2.c_str()).c_str()),  base_mid_crlf2);

    ASSERT_EQUALS(get_decoded_cr_code(get_encoded_cr_code(base_end_crper1.c_str()).c_str()), base_end_crper1);
    ASSERT_EQUALS(get_decoded_cr_code(get_encoded_cr_code(base_mid_crper1.c_str()).c_str()), base_mid_crper1);
    ASSERT_EQUALS(get_decoded_cr_code(get_encoded_cr_code(base_end_crper2.c_str()).c_str()), base_end_crper2);
    ASSERT_EQUALS(get_decoded_cr_code(get_encoded_cr_code(base_mid_crper2.c_str()).c_str()), base_mid_crper2);
}

void test_mask_sensitive_string_with_flag()
{
    auto base = "sensitive"s;
    auto mask = "[SENSITIVE]"s;

    ASSERT_EQUALS(std::string(mask_sensitive_string_with_flag(base.c_str(), true)),  base);
    ASSERT_EQUALS(std::string(mask_sensitive_string_with_flag(base.c_str(), false)), mask);
}

void test_mask_sensitive_header()
{
    auto base_auth_sigv4 = "Authorization: AWS4-HMAC-SHA256 Credential=VALCREDENTIAL, SignedHeaders=VALSIGHEADERS, Signature=VALSIGNATURE"s;
    auto base_auth_sigv2 = "Authorization: AWS VALCREDENTIAL"s;
    auto base_xamz_token = "x-amz-security-token: VALTOKEN"s;
    auto base_xamz_cred = "x-amz-credential: VALCREDENTIAL"s;
    auto base_xamz_sig = "x-amz-signature: VALSIGNATURE"s;
    auto base_xamz_sseckeymd5 = "x-amz-server-side-encryption-customer-key-md5: VALKEYMD5"s;
    auto base_xamz_ssekmsid = "x-amz-server-side-encryption-aws-kms-key-id: VALKEYID"s;
    auto base_xamz_svrsseckey = "x-amz-copy-source-server-side-encryption-customer-key: VALKEY"s;
    auto base_xamz_svrsseckeymd5 = "x-amz-copy-source-server-side-encryption-customer-key-md5: VALKEYMD5"s;
    auto base_xamz_nomask = "x-amz-content-sha256: VALSHA256"s;

    auto mask_auth_sigv4 = "Authorization: AWS4-HMAC-SHA256 Credential=[SENSITIVE], SignedHeaders=[SENSITIVE], Signature=[SENSITIVE]"s;
    auto mask_auth_sigv2 = "Authorization: AWS [SENSITIVE]"s;
    auto mask_xamz_token = "x-amz-security-token: [SENSITIVE]"s;
    auto mask_xamz_cred = "x-amz-credential: [SENSITIVE]"s;
    auto mask_xamz_sig = "x-amz-signature: [SENSITIVE]"s;
    auto mask_xamz_sseckeymd5 = "x-amz-server-side-encryption-customer-key-md5: [SENSITIVE]"s;
    auto mask_xamz_ssekmsid = "x-amz-server-side-encryption-aws-kms-key-id: [SENSITIVE]"s;
    auto mask_xamz_svrsseckey = "x-amz-copy-source-server-side-encryption-customer-key: [SENSITIVE]"s;
    auto mask_xamz_svrsseckeymd5 = "x-amz-copy-source-server-side-encryption-customer-key-md5: [SENSITIVE]"s;
    auto mask_xamz_nomask = "x-amz-content-sha256: VALSHA256"s;

    ASSERT_EQUALS(mask_sensitive_header(base_auth_sigv4.c_str(),         base_auth_sigv4.length()),         mask_auth_sigv4);
    ASSERT_EQUALS(mask_sensitive_header(base_auth_sigv2.c_str(),         base_auth_sigv2.length()),         mask_auth_sigv2);
    ASSERT_EQUALS(mask_sensitive_header(base_xamz_token.c_str(),         base_xamz_token.length()),         mask_xamz_token);
    ASSERT_EQUALS(mask_sensitive_header(base_xamz_cred.c_str(),          base_xamz_cred.length()),          mask_xamz_cred);
    ASSERT_EQUALS(mask_sensitive_header(base_xamz_sig.c_str(),           base_xamz_sig.length()),           mask_xamz_sig);
    ASSERT_EQUALS(mask_sensitive_header(base_xamz_sseckeymd5.c_str(),    base_xamz_sseckeymd5.length()),    mask_xamz_sseckeymd5);
    ASSERT_EQUALS(mask_sensitive_header(base_xamz_ssekmsid.c_str(),      base_xamz_ssekmsid.length()),      mask_xamz_ssekmsid);
    ASSERT_EQUALS(mask_sensitive_header(base_xamz_svrsseckey.c_str(),    base_xamz_svrsseckey.length()),    mask_xamz_svrsseckey);
    ASSERT_EQUALS(mask_sensitive_header(base_xamz_svrsseckeymd5.c_str(), base_xamz_svrsseckeymd5.length()), mask_xamz_svrsseckeymd5);
    ASSERT_EQUALS(mask_sensitive_header(base_xamz_nomask.c_str(),        base_xamz_nomask.length()),        mask_xamz_nomask);
}

void test_mask_sensitive_arg()
{
    auto base_url_http_keyval = "url=http://KEY:SEC@test"s;
    auto base_url_https_keyval = "url=https://KEY:SEC@test"s;
    auto base_url_http_key = "url=http://KEY@test"s;
    auto base_url_https_key = "url=https://KEY@test"s;
    auto base_url_http_no = "url=http://test"s;
    auto base_url_https_no = "url=https://test"s;
    auto base_sslcert_all = "ssl_client_cert=CCERT:CTYPE:CPRIVKEY:CPRIVTYPE:PASSWORD"s;
    auto base_sslcert_wrong_short = "ssl_client_cert=CCERT:CTYPE:CPRIVKEY:CPRIVTYPE"s;

    auto mask_url_http_keyval = "url=http://[SENSITIVE]@test"s;
    auto mask_url_https_keyval = "url=https://[SENSITIVE]@test"s;
    auto mask_url_http_key = "url=http://[SENSITIVE]@test"s;
    auto mask_url_https_key = "url=https://[SENSITIVE]@test"s;
    auto mask_url_http_no = "url=http://test"s;
    auto mask_url_https_no = "url=https://test"s;
    auto mask_sslcert_all = "ssl_client_cert=CCERT:CTYPE:CPRIVKEY:CPRIVTYPE:[SENSITIVE]"s;
    auto mask_sslcert_wrong_short = "ssl_client_cert=CCERT:CTYPE:CPRIVKEY:CPRIVTYPE"s;

    ASSERT_EQUALS(mask_sensitive_arg(base_url_http_keyval.c_str()),     mask_url_http_keyval);
    ASSERT_EQUALS(mask_sensitive_arg(base_url_https_keyval.c_str()),    mask_url_https_keyval);
    ASSERT_EQUALS(mask_sensitive_arg(base_url_http_key.c_str()),        mask_url_http_key);
    ASSERT_EQUALS(mask_sensitive_arg(base_url_https_key.c_str()),       mask_url_https_key);
    ASSERT_EQUALS(mask_sensitive_arg(base_url_http_no.c_str()),         mask_url_http_no);
    ASSERT_EQUALS(mask_sensitive_arg(base_url_https_no.c_str()),        mask_url_https_no);

    ASSERT_EQUALS(mask_sensitive_arg(base_sslcert_all.c_str()),         mask_sslcert_all);
    ASSERT_EQUALS(mask_sensitive_arg(base_sslcert_wrong_short.c_str()), mask_sslcert_wrong_short);
}

int main(int argc, const char *argv[])
{
    S3fsLog singletonLog;

    test_trim();
    test_base64();
    test_strtoofft();
    test_wtf8_encoding();
    test_cr_encoding();
    test_mask_sensitive_string_with_flag();
    test_mask_sensitive_header();
    test_mask_sensitive_arg();

    return 0;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
