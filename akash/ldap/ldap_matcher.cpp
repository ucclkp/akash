// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/ldap/ldap_matcher.h"

#include "utils/unicode.h"


namespace akash {
namespace ldap {

    int LDAPMatcher::caseIgnoreMatch(
        const std::string& attr_val1, const std::string& attr_val2)
    {
        std::string prepared_val1, prepared_val2;
        if (!prepareString(attr_val1, &prepared_val1)) {
            return -1;
        }
        if (!prepareString(attr_val2, &prepared_val2)) {
            return -1;
        }

        if (prepared_val1 == prepared_val2) {
            return 1;
        }
        return 0;
    }

    bool LDAPMatcher::prepareString(const std::string& org, std::string* out) {
        // 2.1 Transcode
        // 当前只支持 UTF8String 和 PrintableString，因此这一步不需要做任何事
        std::u32string u_str;
        if (!utl::Unicode::UTF8ToUTF32(org, &u_str)) {
            return false;
        }

        // 2.2 Map / 2.3 Normalize
        uint8_t cfo_count;
        uint32_t cf_out[4];
        for (auto it = u_str.begin(); it != u_str.end();) {
            auto ch = *it;
            if (ch == 0x00AD || ch == 0x1806 ||
                ch == 0x034F || (ch >= 0x180B && ch<= 0x180D) || (ch >= 0xFF00 && ch <= 0xFE0F) ||
                ch == 0xFFFC)
            {
                it = u_str.erase(it);
                continue;
            } else if ((ch >= 0x0009 && ch <= 0x000D) || ch == 0x0085) {
                *it = 0x0020;
            } else if ((ch >= 0x0000 && ch <= 0x0008) ||
                (ch >= 0x000E && ch <= 0x001F) ||
                (ch >= 0x007F && ch <= 0x0084) ||
                (ch >= 0x0086 && ch <= 0x009F) ||
                ch == 0x06DD || ch == 0x070F || ch == 0x180E ||
                (ch >= 0x200C && ch <= 0x200F) ||
                (ch >= 0x202A && ch <= 0x202E) ||
                (ch >= 0x2060 && ch <= 0x2063) ||
                (ch >= 0x206A && ch <= 0x206F) ||
                ch == 0xFEFF ||
                (ch >= 0xFFF9 && ch <= 0xFFFB) ||
                (ch >= 0x1D173 && ch <= 0x1D17A) ||
                ch == 0xE0001 ||
                (ch >= 0xE0020 && ch <= 0xE007F))
            {
                it = u_str.erase(it);
                continue;
            } else if (ch == 0x200B) {
                it = u_str.erase(it);
                continue;
            } else if (ch == 0x00A0 || ch == 0x1680 ||
                (ch >= 0x2000 && ch <= 0x200A) ||
                (ch >= 0x2028 && ch <= 0x2029) ||
                ch == 0x202F || ch == 0x205F || ch == 0x3000)
            {
                *it = 0x0020;
            }

            caseFoldingWithNFKC(ch, cf_out, &cfo_count);
            if (cfo_count == 1) {
                *it = cf_out[0];
                ++it;
            } else if (cfo_count > 1) {
                *it = cf_out[0];
                ++it;
                it = u_str.insert(it, std::begin(cf_out) + 1, std::begin(cf_out) + cfo_count);
                it += cfo_count - 1;
            }
        }

        // 2.4 Prohibit
        for (auto it = u_str.begin(); it != u_str.end(); ++it) {
            if (isUnassignedCodePoint(*it) || isProhibited(*it)) {
                return false;
            }
        }

        // 2.5 Check bidi

        // 2.6 Insignificant Character Handling
        // 当前只关心 2.6.1 Insignificant Space Handling
        insignificantSpaceHandling(&u_str);

        utl::Unicode::UTF32ToUTF8(u_str, out);
        return true;
    }

    void LDAPMatcher::caseFoldingWithNFKC(uint32_t val, uint32_t out[4], uint8_t* count) {
        switch (val) {
        case 0x0041: out[0] = 0x0061; *count = 1; break; // Case map
        case 0x0042: out[0] = 0x0062; *count = 1; break; // Case map
        case 0x0043: out[0] = 0x0063; *count = 1; break; // Case map
        case 0x0044: out[0] = 0x0064; *count = 1; break; // Case map
        case 0x0045: out[0] = 0x0065; *count = 1; break; // Case map
        case 0x0046: out[0] = 0x0066; *count = 1; break; // Case map
        case 0x0047: out[0] = 0x0067; *count = 1; break; // Case map
        case 0x0048: out[0] = 0x0068; *count = 1; break; // Case map
        case 0x0049: out[0] = 0x0069; *count = 1; break; // Case map
        case 0x004A: out[0] = 0x006A; *count = 1; break; // Case map
        case 0x004B: out[0] = 0x006B; *count = 1; break; // Case map
        case 0x004C: out[0] = 0x006C; *count = 1; break; // Case map
        case 0x004D: out[0] = 0x006D; *count = 1; break; // Case map
        case 0x004E: out[0] = 0x006E; *count = 1; break; // Case map
        case 0x004F: out[0] = 0x006F; *count = 1; break; // Case map
        case 0x0050: out[0] = 0x0070; *count = 1; break; // Case map
        case 0x0051: out[0] = 0x0071; *count = 1; break; // Case map
        case 0x0052: out[0] = 0x0072; *count = 1; break; // Case map
        case 0x0053: out[0] = 0x0073; *count = 1; break; // Case map
        case 0x0054: out[0] = 0x0074; *count = 1; break; // Case map
        case 0x0055: out[0] = 0x0075; *count = 1; break; // Case map
        case 0x0056: out[0] = 0x0076; *count = 1; break; // Case map
        case 0x0057: out[0] = 0x0077; *count = 1; break; // Case map
        case 0x0058: out[0] = 0x0078; *count = 1; break; // Case map
        case 0x0059: out[0] = 0x0079; *count = 1; break; // Case map
        case 0x005A: out[0] = 0x007A; *count = 1; break; // Case map
        case 0x00B5: out[0] = 0x03BC; *count = 1; break; // Case map
        case 0x00C0: out[0] = 0x00E0; *count = 1; break; // Case map
        case 0x00C1: out[0] = 0x00E1; *count = 1; break; // Case map
        case 0x00C2: out[0] = 0x00E2; *count = 1; break; // Case map
        case 0x00C3: out[0] = 0x00E3; *count = 1; break; // Case map
        case 0x00C4: out[0] = 0x00E4; *count = 1; break; // Case map
        case 0x00C5: out[0] = 0x00E5; *count = 1; break; // Case map
        case 0x00C6: out[0] = 0x00E6; *count = 1; break; // Case map
        case 0x00C7: out[0] = 0x00E7; *count = 1; break; // Case map
        case 0x00C8: out[0] = 0x00E8; *count = 1; break; // Case map
        case 0x00C9: out[0] = 0x00E9; *count = 1; break; // Case map
        case 0x00CA: out[0] = 0x00EA; *count = 1; break; // Case map
        case 0x00CB: out[0] = 0x00EB; *count = 1; break; // Case map
        case 0x00CC: out[0] = 0x00EC; *count = 1; break; // Case map
        case 0x00CD: out[0] = 0x00ED; *count = 1; break; // Case map
        case 0x00CE: out[0] = 0x00EE; *count = 1; break; // Case map
        case 0x00CF: out[0] = 0x00EF; *count = 1; break; // Case map
        case 0x00D0: out[0] = 0x00F0; *count = 1; break; // Case map
        case 0x00D1: out[0] = 0x00F1; *count = 1; break; // Case map
        case 0x00D2: out[0] = 0x00F2; *count = 1; break; // Case map
        case 0x00D3: out[0] = 0x00F3; *count = 1; break; // Case map
        case 0x00D4: out[0] = 0x00F4; *count = 1; break; // Case map
        case 0x00D5: out[0] = 0x00F5; *count = 1; break; // Case map
        case 0x00D6: out[0] = 0x00F6; *count = 1; break; // Case map
        case 0x00D8: out[0] = 0x00F8; *count = 1; break; // Case map
        case 0x00D9: out[0] = 0x00F9; *count = 1; break; // Case map
        case 0x00DA: out[0] = 0x00FA; *count = 1; break; // Case map
        case 0x00DB: out[0] = 0x00FB; *count = 1; break; // Case map
        case 0x00DC: out[0] = 0x00FC; *count = 1; break; // Case map
        case 0x00DD: out[0] = 0x00FD; *count = 1; break; // Case map
        case 0x00DE: out[0] = 0x00FE; *count = 1; break; // Case map
        case 0x00DF: out[0] = 0x0073; out[1] = 0x0073; *count = 2; break; // Case map
        case 0x0100: out[0] = 0x0101; *count = 1; break; // Case map
        case 0x0102: out[0] = 0x0103; *count = 1; break; // Case map
        case 0x0104: out[0] = 0x0105; *count = 1; break; // Case map
        case 0x0106: out[0] = 0x0107; *count = 1; break; // Case map
        case 0x0108: out[0] = 0x0109; *count = 1; break; // Case map
        case 0x010A: out[0] = 0x010B; *count = 1; break; // Case map
        case 0x010C: out[0] = 0x010D; *count = 1; break; // Case map
        case 0x010E: out[0] = 0x010F; *count = 1; break; // Case map
        case 0x0110: out[0] = 0x0111; *count = 1; break; // Case map
        case 0x0112: out[0] = 0x0113; *count = 1; break; // Case map
        case 0x0114: out[0] = 0x0115; *count = 1; break; // Case map
        case 0x0116: out[0] = 0x0117; *count = 1; break; // Case map
        case 0x0118: out[0] = 0x0119; *count = 1; break; // Case map
        case 0x011A: out[0] = 0x011B; *count = 1; break; // Case map
        case 0x011C: out[0] = 0x011D; *count = 1; break; // Case map
        case 0x011E: out[0] = 0x011F; *count = 1; break; // Case map
        case 0x0120: out[0] = 0x0121; *count = 1; break; // Case map
        case 0x0122: out[0] = 0x0123; *count = 1; break; // Case map
        case 0x0124: out[0] = 0x0125; *count = 1; break; // Case map
        case 0x0126: out[0] = 0x0127; *count = 1; break; // Case map
        case 0x0128: out[0] = 0x0129; *count = 1; break; // Case map
        case 0x012A: out[0] = 0x012B; *count = 1; break; // Case map
        case 0x012C: out[0] = 0x012D; *count = 1; break; // Case map
        case 0x012E: out[0] = 0x012F; *count = 1; break; // Case map
        case 0x0130: out[0] = 0x0069; out[1] = 0x0307; *count = 2; break; // Case map
        case 0x0132: out[0] = 0x0133; *count = 1; break; // Case map
        case 0x0134: out[0] = 0x0135; *count = 1; break; // Case map
        case 0x0136: out[0] = 0x0137; *count = 1; break; // Case map
        case 0x0139: out[0] = 0x013A; *count = 1; break; // Case map
        case 0x013B: out[0] = 0x013C; *count = 1; break; // Case map
        case 0x013D: out[0] = 0x013E; *count = 1; break; // Case map
        case 0x013F: out[0] = 0x0140; *count = 1; break; // Case map
        case 0x0141: out[0] = 0x0142; *count = 1; break; // Case map
        case 0x0143: out[0] = 0x0144; *count = 1; break; // Case map
        case 0x0145: out[0] = 0x0146; *count = 1; break; // Case map
        case 0x0147: out[0] = 0x0148; *count = 1; break; // Case map
        case 0x0149: out[0] = 0x02BC; out[1] = 0x006E; *count = 2; break; // Case map
        case 0x014A: out[0] = 0x014B; *count = 1; break; // Case map
        case 0x014C: out[0] = 0x014D; *count = 1; break; // Case map
        case 0x014E: out[0] = 0x014F; *count = 1; break; // Case map
        case 0x0150: out[0] = 0x0151; *count = 1; break; // Case map
        case 0x0152: out[0] = 0x0153; *count = 1; break; // Case map
        case 0x0154: out[0] = 0x0155; *count = 1; break; // Case map
        case 0x0156: out[0] = 0x0157; *count = 1; break; // Case map
        case 0x0158: out[0] = 0x0159; *count = 1; break; // Case map
        case 0x015A: out[0] = 0x015B; *count = 1; break; // Case map
        case 0x015C: out[0] = 0x015D; *count = 1; break; // Case map
        case 0x015E: out[0] = 0x015F; *count = 1; break; // Case map
        case 0x0160: out[0] = 0x0161; *count = 1; break; // Case map
        case 0x0162: out[0] = 0x0163; *count = 1; break; // Case map
        case 0x0164: out[0] = 0x0165; *count = 1; break; // Case map
        case 0x0166: out[0] = 0x0167; *count = 1; break; // Case map
        case 0x0168: out[0] = 0x0169; *count = 1; break; // Case map
        case 0x016A: out[0] = 0x016B; *count = 1; break; // Case map
        case 0x016C: out[0] = 0x016D; *count = 1; break; // Case map
        case 0x016E: out[0] = 0x016F; *count = 1; break; // Case map
        case 0x0170: out[0] = 0x0171; *count = 1; break; // Case map
        case 0x0172: out[0] = 0x0173; *count = 1; break; // Case map
        case 0x0174: out[0] = 0x0175; *count = 1; break; // Case map
        case 0x0176: out[0] = 0x0177; *count = 1; break; // Case map
        case 0x0178: out[0] = 0x00FF; *count = 1; break; // Case map
        case 0x0179: out[0] = 0x017A; *count = 1; break; // Case map
        case 0x017B: out[0] = 0x017C; *count = 1; break; // Case map
        case 0x017D: out[0] = 0x017E; *count = 1; break; // Case map
        case 0x017F: out[0] = 0x0073; *count = 1; break; // Case map
        case 0x0181: out[0] = 0x0253; *count = 1; break; // Case map
        case 0x0182: out[0] = 0x0183; *count = 1; break; // Case map
        case 0x0184: out[0] = 0x0185; *count = 1; break; // Case map
        case 0x0186: out[0] = 0x0254; *count = 1; break; // Case map
        case 0x0187: out[0] = 0x0188; *count = 1; break; // Case map
        case 0x0189: out[0] = 0x0256; *count = 1; break; // Case map
        case 0x018A: out[0] = 0x0257; *count = 1; break; // Case map
        case 0x018B: out[0] = 0x018C; *count = 1; break; // Case map
        case 0x018E: out[0] = 0x01DD; *count = 1; break; // Case map
        case 0x018F: out[0] = 0x0259; *count = 1; break; // Case map
        case 0x0190: out[0] = 0x025B; *count = 1; break; // Case map
        case 0x0191: out[0] = 0x0192; *count = 1; break; // Case map
        case 0x0193: out[0] = 0x0260; *count = 1; break; // Case map
        case 0x0194: out[0] = 0x0263; *count = 1; break; // Case map
        case 0x0196: out[0] = 0x0269; *count = 1; break; // Case map
        case 0x0197: out[0] = 0x0268; *count = 1; break; // Case map
        case 0x0198: out[0] = 0x0199; *count = 1; break; // Case map
        case 0x019C: out[0] = 0x026F; *count = 1; break; // Case map
        case 0x019D: out[0] = 0x0272; *count = 1; break; // Case map
        case 0x019F: out[0] = 0x0275; *count = 1; break; // Case map
        case 0x01A0: out[0] = 0x01A1; *count = 1; break; // Case map
        case 0x01A2: out[0] = 0x01A3; *count = 1; break; // Case map
        case 0x01A4: out[0] = 0x01A5; *count = 1; break; // Case map
        case 0x01A6: out[0] = 0x0280; *count = 1; break; // Case map
        case 0x01A7: out[0] = 0x01A8; *count = 1; break; // Case map
        case 0x01A9: out[0] = 0x0283; *count = 1; break; // Case map
        case 0x01AC: out[0] = 0x01AD; *count = 1; break; // Case map
        case 0x01AE: out[0] = 0x0288; *count = 1; break; // Case map
        case 0x01AF: out[0] = 0x01B0; *count = 1; break; // Case map
        case 0x01B1: out[0] = 0x028A; *count = 1; break; // Case map
        case 0x01B2: out[0] = 0x028B; *count = 1; break; // Case map
        case 0x01B3: out[0] = 0x01B4; *count = 1; break; // Case map
        case 0x01B5: out[0] = 0x01B6; *count = 1; break; // Case map
        case 0x01B7: out[0] = 0x0292; *count = 1; break; // Case map
        case 0x01B8: out[0] = 0x01B9; *count = 1; break; // Case map
        case 0x01BC: out[0] = 0x01BD; *count = 1; break; // Case map
        case 0x01C4: out[0] = 0x01C6; *count = 1; break; // Case map
        case 0x01C5: out[0] = 0x01C6; *count = 1; break; // Case map
        case 0x01C7: out[0] = 0x01C9; *count = 1; break; // Case map
        case 0x01C8: out[0] = 0x01C9; *count = 1; break; // Case map
        case 0x01CA: out[0] = 0x01CC; *count = 1; break; // Case map
        case 0x01CB: out[0] = 0x01CC; *count = 1; break; // Case map
        case 0x01CD: out[0] = 0x01CE; *count = 1; break; // Case map
        case 0x01CF: out[0] = 0x01D0; *count = 1; break; // Case map
        case 0x01D1: out[0] = 0x01D2; *count = 1; break; // Case map
        case 0x01D3: out[0] = 0x01D4; *count = 1; break; // Case map
        case 0x01D5: out[0] = 0x01D6; *count = 1; break; // Case map
        case 0x01D7: out[0] = 0x01D8; *count = 1; break; // Case map
        case 0x01D9: out[0] = 0x01DA; *count = 1; break; // Case map
        case 0x01DB: out[0] = 0x01DC; *count = 1; break; // Case map
        case 0x01DE: out[0] = 0x01DF; *count = 1; break; // Case map
        case 0x01E0: out[0] = 0x01E1; *count = 1; break; // Case map
        case 0x01E2: out[0] = 0x01E3; *count = 1; break; // Case map
        case 0x01E4: out[0] = 0x01E5; *count = 1; break; // Case map
        case 0x01E6: out[0] = 0x01E7; *count = 1; break; // Case map
        case 0x01E8: out[0] = 0x01E9; *count = 1; break; // Case map
        case 0x01EA: out[0] = 0x01EB; *count = 1; break; // Case map
        case 0x01EC: out[0] = 0x01ED; *count = 1; break; // Case map
        case 0x01EE: out[0] = 0x01EF; *count = 1; break; // Case map
        case 0x01F0: out[0] = 0x006A; out[1] = 0x030C; *count = 2; break; // Case map
        case 0x01F1: out[0] = 0x01F3; *count = 1; break; // Case map
        case 0x01F2: out[0] = 0x01F3; *count = 1; break; // Case map
        case 0x01F4: out[0] = 0x01F5; *count = 1; break; // Case map
        case 0x01F6: out[0] = 0x0195; *count = 1; break; // Case map
        case 0x01F7: out[0] = 0x01BF; *count = 1; break; // Case map
        case 0x01F8: out[0] = 0x01F9; *count = 1; break; // Case map
        case 0x01FA: out[0] = 0x01FB; *count = 1; break; // Case map
        case 0x01FC: out[0] = 0x01FD; *count = 1; break; // Case map
        case 0x01FE: out[0] = 0x01FF; *count = 1; break; // Case map
        case 0x0200: out[0] = 0x0201; *count = 1; break; // Case map
        case 0x0202: out[0] = 0x0203; *count = 1; break; // Case map
        case 0x0204: out[0] = 0x0205; *count = 1; break; // Case map
        case 0x0206: out[0] = 0x0207; *count = 1; break; // Case map
        case 0x0208: out[0] = 0x0209; *count = 1; break; // Case map
        case 0x020A: out[0] = 0x020B; *count = 1; break; // Case map
        case 0x020C: out[0] = 0x020D; *count = 1; break; // Case map
        case 0x020E: out[0] = 0x020F; *count = 1; break; // Case map
        case 0x0210: out[0] = 0x0211; *count = 1; break; // Case map
        case 0x0212: out[0] = 0x0213; *count = 1; break; // Case map
        case 0x0214: out[0] = 0x0215; *count = 1; break; // Case map
        case 0x0216: out[0] = 0x0217; *count = 1; break; // Case map
        case 0x0218: out[0] = 0x0219; *count = 1; break; // Case map
        case 0x021A: out[0] = 0x021B; *count = 1; break; // Case map
        case 0x021C: out[0] = 0x021D; *count = 1; break; // Case map
        case 0x021E: out[0] = 0x021F; *count = 1; break; // Case map
        case 0x0220: out[0] = 0x019E; *count = 1; break; // Case map
        case 0x0222: out[0] = 0x0223; *count = 1; break; // Case map
        case 0x0224: out[0] = 0x0225; *count = 1; break; // Case map
        case 0x0226: out[0] = 0x0227; *count = 1; break; // Case map
        case 0x0228: out[0] = 0x0229; *count = 1; break; // Case map
        case 0x022A: out[0] = 0x022B; *count = 1; break; // Case map
        case 0x022C: out[0] = 0x022D; *count = 1; break; // Case map
        case 0x022E: out[0] = 0x022F; *count = 1; break; // Case map
        case 0x0230: out[0] = 0x0231; *count = 1; break; // Case map
        case 0x0232: out[0] = 0x0233; *count = 1; break; // Case map
        case 0x0345: out[0] = 0x03B9; *count = 1; break; // Case map
        case 0x037A: out[0] = 0x0020; out[1] = 0x03B9; *count = 2; break; // Additional folding
        case 0x0386: out[0] = 0x03AC; *count = 1; break; // Case map
        case 0x0388: out[0] = 0x03AD; *count = 1; break; // Case map
        case 0x0389: out[0] = 0x03AE; *count = 1; break; // Case map
        case 0x038A: out[0] = 0x03AF; *count = 1; break; // Case map
        case 0x038C: out[0] = 0x03CC; *count = 1; break; // Case map
        case 0x038E: out[0] = 0x03CD; *count = 1; break; // Case map
        case 0x038F: out[0] = 0x03CE; *count = 1; break; // Case map
        case 0x0390: out[0] = 0x03B9; out[1] = 0x0308; out[2] = 0x0301; *count = 3; break; // Case map
        case 0x0391: out[0] = 0x03B1; *count = 1; break; // Case map
        case 0x0392: out[0] = 0x03B2; *count = 1; break; // Case map
        case 0x0393: out[0] = 0x03B3; *count = 1; break; // Case map
        case 0x0394: out[0] = 0x03B4; *count = 1; break; // Case map
        case 0x0395: out[0] = 0x03B5; *count = 1; break; // Case map
        case 0x0396: out[0] = 0x03B6; *count = 1; break; // Case map
        case 0x0397: out[0] = 0x03B7; *count = 1; break; // Case map
        case 0x0398: out[0] = 0x03B8; *count = 1; break; // Case map
        case 0x0399: out[0] = 0x03B9; *count = 1; break; // Case map
        case 0x039A: out[0] = 0x03BA; *count = 1; break; // Case map
        case 0x039B: out[0] = 0x03BB; *count = 1; break; // Case map
        case 0x039C: out[0] = 0x03BC; *count = 1; break; // Case map
        case 0x039D: out[0] = 0x03BD; *count = 1; break; // Case map
        case 0x039E: out[0] = 0x03BE; *count = 1; break; // Case map
        case 0x039F: out[0] = 0x03BF; *count = 1; break; // Case map
        case 0x03A0: out[0] = 0x03C0; *count = 1; break; // Case map
        case 0x03A1: out[0] = 0x03C1; *count = 1; break; // Case map
        case 0x03A3: out[0] = 0x03C3; *count = 1; break; // Case map
        case 0x03A4: out[0] = 0x03C4; *count = 1; break; // Case map
        case 0x03A5: out[0] = 0x03C5; *count = 1; break; // Case map
        case 0x03A6: out[0] = 0x03C6; *count = 1; break; // Case map
        case 0x03A7: out[0] = 0x03C7; *count = 1; break; // Case map
        case 0x03A8: out[0] = 0x03C8; *count = 1; break; // Case map
        case 0x03A9: out[0] = 0x03C9; *count = 1; break; // Case map
        case 0x03AA: out[0] = 0x03CA; *count = 1; break; // Case map
        case 0x03AB: out[0] = 0x03CB; *count = 1; break; // Case map
        case 0x03B0: out[0] = 0x03C5; out[1] = 0x0308; out[2] = 0x0301; *count = 3; break; // Case map
        case 0x03C2: out[0] = 0x03C3; *count = 1; break; // Case map
        case 0x03D0: out[0] = 0x03B2; *count = 1; break; // Case map
        case 0x03D1: out[0] = 0x03B8; *count = 1; break; // Case map
        case 0x03D2: out[0] = 0x03C5; *count = 1; break; // Additional folding
        case 0x03D3: out[0] = 0x03CD; *count = 1; break; // Additional folding
        case 0x03D4: out[0] = 0x03CB; *count = 1; break; // Additional folding
        case 0x03D5: out[0] = 0x03C6; *count = 1; break; // Case map
        case 0x03D6: out[0] = 0x03C0; *count = 1; break; // Case map
        case 0x03D8: out[0] = 0x03D9; *count = 1; break; // Case map
        case 0x03DA: out[0] = 0x03DB; *count = 1; break; // Case map
        case 0x03DC: out[0] = 0x03DD; *count = 1; break; // Case map
        case 0x03DE: out[0] = 0x03DF; *count = 1; break; // Case map
        case 0x03E0: out[0] = 0x03E1; *count = 1; break; // Case map
        case 0x03E2: out[0] = 0x03E3; *count = 1; break; // Case map
        case 0x03E4: out[0] = 0x03E5; *count = 1; break; // Case map
        case 0x03E6: out[0] = 0x03E7; *count = 1; break; // Case map
        case 0x03E8: out[0] = 0x03E9; *count = 1; break; // Case map
        case 0x03EA: out[0] = 0x03EB; *count = 1; break; // Case map
        case 0x03EC: out[0] = 0x03ED; *count = 1; break; // Case map
        case 0x03EE: out[0] = 0x03EF; *count = 1; break; // Case map
        case 0x03F0: out[0] = 0x03BA; *count = 1; break; // Case map
        case 0x03F1: out[0] = 0x03C1; *count = 1; break; // Case map
        case 0x03F2: out[0] = 0x03C3; *count = 1; break; // Case map
        case 0x03F4: out[0] = 0x03B8; *count = 1; break; // Case map
        case 0x03F5: out[0] = 0x03B5; *count = 1; break; // Case map
        case 0x0400: out[0] = 0x0450; *count = 1; break; // Case map
        case 0x0401: out[0] = 0x0451; *count = 1; break; // Case map
        case 0x0402: out[0] = 0x0452; *count = 1; break; // Case map
        case 0x0403: out[0] = 0x0453; *count = 1; break; // Case map
        case 0x0404: out[0] = 0x0454; *count = 1; break; // Case map
        case 0x0405: out[0] = 0x0455; *count = 1; break; // Case map
        case 0x0406: out[0] = 0x0456; *count = 1; break; // Case map
        case 0x0407: out[0] = 0x0457; *count = 1; break; // Case map
        case 0x0408: out[0] = 0x0458; *count = 1; break; // Case map
        case 0x0409: out[0] = 0x0459; *count = 1; break; // Case map
        case 0x040A: out[0] = 0x045A; *count = 1; break; // Case map
        case 0x040B: out[0] = 0x045B; *count = 1; break; // Case map
        case 0x040C: out[0] = 0x045C; *count = 1; break; // Case map
        case 0x040D: out[0] = 0x045D; *count = 1; break; // Case map
        case 0x040E: out[0] = 0x045E; *count = 1; break; // Case map
        case 0x040F: out[0] = 0x045F; *count = 1; break; // Case map
        case 0x0410: out[0] = 0x0430; *count = 1; break; // Case map
        case 0x0411: out[0] = 0x0431; *count = 1; break; // Case map
        case 0x0412: out[0] = 0x0432; *count = 1; break; // Case map
        case 0x0413: out[0] = 0x0433; *count = 1; break; // Case map
        case 0x0414: out[0] = 0x0434; *count = 1; break; // Case map
        case 0x0415: out[0] = 0x0435; *count = 1; break; // Case map
        case 0x0416: out[0] = 0x0436; *count = 1; break; // Case map
        case 0x0417: out[0] = 0x0437; *count = 1; break; // Case map
        case 0x0418: out[0] = 0x0438; *count = 1; break; // Case map
        case 0x0419: out[0] = 0x0439; *count = 1; break; // Case map
        case 0x041A: out[0] = 0x043A; *count = 1; break; // Case map
        case 0x041B: out[0] = 0x043B; *count = 1; break; // Case map
        case 0x041C: out[0] = 0x043C; *count = 1; break; // Case map
        case 0x041D: out[0] = 0x043D; *count = 1; break; // Case map
        case 0x041E: out[0] = 0x043E; *count = 1; break; // Case map
        case 0x041F: out[0] = 0x043F; *count = 1; break; // Case map
        case 0x0420: out[0] = 0x0440; *count = 1; break; // Case map
        case 0x0421: out[0] = 0x0441; *count = 1; break; // Case map
        case 0x0422: out[0] = 0x0442; *count = 1; break; // Case map
        case 0x0423: out[0] = 0x0443; *count = 1; break; // Case map
        case 0x0424: out[0] = 0x0444; *count = 1; break; // Case map
        case 0x0425: out[0] = 0x0445; *count = 1; break; // Case map
        case 0x0426: out[0] = 0x0446; *count = 1; break; // Case map
        case 0x0427: out[0] = 0x0447; *count = 1; break; // Case map
        case 0x0428: out[0] = 0x0448; *count = 1; break; // Case map
        case 0x0429: out[0] = 0x0449; *count = 1; break; // Case map
        case 0x042A: out[0] = 0x044A; *count = 1; break; // Case map
        case 0x042B: out[0] = 0x044B; *count = 1; break; // Case map
        case 0x042C: out[0] = 0x044C; *count = 1; break; // Case map
        case 0x042D: out[0] = 0x044D; *count = 1; break; // Case map
        case 0x042E: out[0] = 0x044E; *count = 1; break; // Case map
        case 0x042F: out[0] = 0x044F; *count = 1; break; // Case map
        case 0x0460: out[0] = 0x0461; *count = 1; break; // Case map
        case 0x0462: out[0] = 0x0463; *count = 1; break; // Case map
        case 0x0464: out[0] = 0x0465; *count = 1; break; // Case map
        case 0x0466: out[0] = 0x0467; *count = 1; break; // Case map
        case 0x0468: out[0] = 0x0469; *count = 1; break; // Case map
        case 0x046A: out[0] = 0x046B; *count = 1; break; // Case map
        case 0x046C: out[0] = 0x046D; *count = 1; break; // Case map
        case 0x046E: out[0] = 0x046F; *count = 1; break; // Case map
        case 0x0470: out[0] = 0x0471; *count = 1; break; // Case map
        case 0x0472: out[0] = 0x0473; *count = 1; break; // Case map
        case 0x0474: out[0] = 0x0475; *count = 1; break; // Case map
        case 0x0476: out[0] = 0x0477; *count = 1; break; // Case map
        case 0x0478: out[0] = 0x0479; *count = 1; break; // Case map
        case 0x047A: out[0] = 0x047B; *count = 1; break; // Case map
        case 0x047C: out[0] = 0x047D; *count = 1; break; // Case map
        case 0x047E: out[0] = 0x047F; *count = 1; break; // Case map
        case 0x0480: out[0] = 0x0481; *count = 1; break; // Case map
        case 0x048A: out[0] = 0x048B; *count = 1; break; // Case map
        case 0x048C: out[0] = 0x048D; *count = 1; break; // Case map
        case 0x048E: out[0] = 0x048F; *count = 1; break; // Case map
        case 0x0490: out[0] = 0x0491; *count = 1; break; // Case map
        case 0x0492: out[0] = 0x0493; *count = 1; break; // Case map
        case 0x0494: out[0] = 0x0495; *count = 1; break; // Case map
        case 0x0496: out[0] = 0x0497; *count = 1; break; // Case map
        case 0x0498: out[0] = 0x0499; *count = 1; break; // Case map
        case 0x049A: out[0] = 0x049B; *count = 1; break; // Case map
        case 0x049C: out[0] = 0x049D; *count = 1; break; // Case map
        case 0x049E: out[0] = 0x049F; *count = 1; break; // Case map
        case 0x04A0: out[0] = 0x04A1; *count = 1; break; // Case map
        case 0x04A2: out[0] = 0x04A3; *count = 1; break; // Case map
        case 0x04A4: out[0] = 0x04A5; *count = 1; break; // Case map
        case 0x04A6: out[0] = 0x04A7; *count = 1; break; // Case map
        case 0x04A8: out[0] = 0x04A9; *count = 1; break; // Case map
        case 0x04AA: out[0] = 0x04AB; *count = 1; break; // Case map
        case 0x04AC: out[0] = 0x04AD; *count = 1; break; // Case map
        case 0x04AE: out[0] = 0x04AF; *count = 1; break; // Case map
        case 0x04B0: out[0] = 0x04B1; *count = 1; break; // Case map
        case 0x04B2: out[0] = 0x04B3; *count = 1; break; // Case map
        case 0x04B4: out[0] = 0x04B5; *count = 1; break; // Case map
        case 0x04B6: out[0] = 0x04B7; *count = 1; break; // Case map
        case 0x04B8: out[0] = 0x04B9; *count = 1; break; // Case map
        case 0x04BA: out[0] = 0x04BB; *count = 1; break; // Case map
        case 0x04BC: out[0] = 0x04BD; *count = 1; break; // Case map
        case 0x04BE: out[0] = 0x04BF; *count = 1; break; // Case map
        case 0x04C1: out[0] = 0x04C2; *count = 1; break; // Case map
        case 0x04C3: out[0] = 0x04C4; *count = 1; break; // Case map
        case 0x04C5: out[0] = 0x04C6; *count = 1; break; // Case map
        case 0x04C7: out[0] = 0x04C8; *count = 1; break; // Case map
        case 0x04C9: out[0] = 0x04CA; *count = 1; break; // Case map
        case 0x04CB: out[0] = 0x04CC; *count = 1; break; // Case map
        case 0x04CD: out[0] = 0x04CE; *count = 1; break; // Case map
        case 0x04D0: out[0] = 0x04D1; *count = 1; break; // Case map
        case 0x04D2: out[0] = 0x04D3; *count = 1; break; // Case map
        case 0x04D4: out[0] = 0x04D5; *count = 1; break; // Case map
        case 0x04D6: out[0] = 0x04D7; *count = 1; break; // Case map
        case 0x04D8: out[0] = 0x04D9; *count = 1; break; // Case map
        case 0x04DA: out[0] = 0x04DB; *count = 1; break; // Case map
        case 0x04DC: out[0] = 0x04DD; *count = 1; break; // Case map
        case 0x04DE: out[0] = 0x04DF; *count = 1; break; // Case map
        case 0x04E0: out[0] = 0x04E1; *count = 1; break; // Case map
        case 0x04E2: out[0] = 0x04E3; *count = 1; break; // Case map
        case 0x04E4: out[0] = 0x04E5; *count = 1; break; // Case map
        case 0x04E6: out[0] = 0x04E7; *count = 1; break; // Case map
        case 0x04E8: out[0] = 0x04E9; *count = 1; break; // Case map
        case 0x04EA: out[0] = 0x04EB; *count = 1; break; // Case map
        case 0x04EC: out[0] = 0x04ED; *count = 1; break; // Case map
        case 0x04EE: out[0] = 0x04EF; *count = 1; break; // Case map
        case 0x04F0: out[0] = 0x04F1; *count = 1; break; // Case map
        case 0x04F2: out[0] = 0x04F3; *count = 1; break; // Case map
        case 0x04F4: out[0] = 0x04F5; *count = 1; break; // Case map
        case 0x04F8: out[0] = 0x04F9; *count = 1; break; // Case map
        case 0x0500: out[0] = 0x0501; *count = 1; break; // Case map
        case 0x0502: out[0] = 0x0503; *count = 1; break; // Case map
        case 0x0504: out[0] = 0x0505; *count = 1; break; // Case map
        case 0x0506: out[0] = 0x0507; *count = 1; break; // Case map
        case 0x0508: out[0] = 0x0509; *count = 1; break; // Case map
        case 0x050A: out[0] = 0x050B; *count = 1; break; // Case map
        case 0x050C: out[0] = 0x050D; *count = 1; break; // Case map
        case 0x050E: out[0] = 0x050F; *count = 1; break; // Case map
        case 0x0531: out[0] = 0x0561; *count = 1; break; // Case map
        case 0x0532: out[0] = 0x0562; *count = 1; break; // Case map
        case 0x0533: out[0] = 0x0563; *count = 1; break; // Case map
        case 0x0534: out[0] = 0x0564; *count = 1; break; // Case map
        case 0x0535: out[0] = 0x0565; *count = 1; break; // Case map
        case 0x0536: out[0] = 0x0566; *count = 1; break; // Case map
        case 0x0537: out[0] = 0x0567; *count = 1; break; // Case map
        case 0x0538: out[0] = 0x0568; *count = 1; break; // Case map
        case 0x0539: out[0] = 0x0569; *count = 1; break; // Case map
        case 0x053A: out[0] = 0x056A; *count = 1; break; // Case map
        case 0x053B: out[0] = 0x056B; *count = 1; break; // Case map
        case 0x053C: out[0] = 0x056C; *count = 1; break; // Case map
        case 0x053D: out[0] = 0x056D; *count = 1; break; // Case map
        case 0x053E: out[0] = 0x056E; *count = 1; break; // Case map
        case 0x053F: out[0] = 0x056F; *count = 1; break; // Case map
        case 0x0540: out[0] = 0x0570; *count = 1; break; // Case map
        case 0x0541: out[0] = 0x0571; *count = 1; break; // Case map
        case 0x0542: out[0] = 0x0572; *count = 1; break; // Case map
        case 0x0543: out[0] = 0x0573; *count = 1; break; // Case map
        case 0x0544: out[0] = 0x0574; *count = 1; break; // Case map
        case 0x0545: out[0] = 0x0575; *count = 1; break; // Case map
        case 0x0546: out[0] = 0x0576; *count = 1; break; // Case map
        case 0x0547: out[0] = 0x0577; *count = 1; break; // Case map
        case 0x0548: out[0] = 0x0578; *count = 1; break; // Case map
        case 0x0549: out[0] = 0x0579; *count = 1; break; // Case map
        case 0x054A: out[0] = 0x057A; *count = 1; break; // Case map
        case 0x054B: out[0] = 0x057B; *count = 1; break; // Case map
        case 0x054C: out[0] = 0x057C; *count = 1; break; // Case map
        case 0x054D: out[0] = 0x057D; *count = 1; break; // Case map
        case 0x054E: out[0] = 0x057E; *count = 1; break; // Case map
        case 0x054F: out[0] = 0x057F; *count = 1; break; // Case map
        case 0x0550: out[0] = 0x0580; *count = 1; break; // Case map
        case 0x0551: out[0] = 0x0581; *count = 1; break; // Case map
        case 0x0552: out[0] = 0x0582; *count = 1; break; // Case map
        case 0x0553: out[0] = 0x0583; *count = 1; break; // Case map
        case 0x0554: out[0] = 0x0584; *count = 1; break; // Case map
        case 0x0555: out[0] = 0x0585; *count = 1; break; // Case map
        case 0x0556: out[0] = 0x0586; *count = 1; break; // Case map
        case 0x0587: out[0] = 0x0565; out[1] = 0x0582; *count = 2; break; // Case map
        case 0x1E00: out[0] = 0x1E01; *count = 1; break; // Case map
        case 0x1E02: out[0] = 0x1E03; *count = 1; break; // Case map
        case 0x1E04: out[0] = 0x1E05; *count = 1; break; // Case map
        case 0x1E06: out[0] = 0x1E07; *count = 1; break; // Case map
        case 0x1E08: out[0] = 0x1E09; *count = 1; break; // Case map
        case 0x1E0A: out[0] = 0x1E0B; *count = 1; break; // Case map
        case 0x1E0C: out[0] = 0x1E0D; *count = 1; break; // Case map
        case 0x1E0E: out[0] = 0x1E0F; *count = 1; break; // Case map
        case 0x1E10: out[0] = 0x1E11; *count = 1; break; // Case map
        case 0x1E12: out[0] = 0x1E13; *count = 1; break; // Case map
        case 0x1E14: out[0] = 0x1E15; *count = 1; break; // Case map
        case 0x1E16: out[0] = 0x1E17; *count = 1; break; // Case map
        case 0x1E18: out[0] = 0x1E19; *count = 1; break; // Case map
        case 0x1E1A: out[0] = 0x1E1B; *count = 1; break; // Case map
        case 0x1E1C: out[0] = 0x1E1D; *count = 1; break; // Case map
        case 0x1E1E: out[0] = 0x1E1F; *count = 1; break; // Case map
        case 0x1E20: out[0] = 0x1E21; *count = 1; break; // Case map
        case 0x1E22: out[0] = 0x1E23; *count = 1; break; // Case map
        case 0x1E24: out[0] = 0x1E25; *count = 1; break; // Case map
        case 0x1E26: out[0] = 0x1E27; *count = 1; break; // Case map
        case 0x1E28: out[0] = 0x1E29; *count = 1; break; // Case map
        case 0x1E2A: out[0] = 0x1E2B; *count = 1; break; // Case map
        case 0x1E2C: out[0] = 0x1E2D; *count = 1; break; // Case map
        case 0x1E2E: out[0] = 0x1E2F; *count = 1; break; // Case map
        case 0x1E30: out[0] = 0x1E31; *count = 1; break; // Case map
        case 0x1E32: out[0] = 0x1E33; *count = 1; break; // Case map
        case 0x1E34: out[0] = 0x1E35; *count = 1; break; // Case map
        case 0x1E36: out[0] = 0x1E37; *count = 1; break; // Case map
        case 0x1E38: out[0] = 0x1E39; *count = 1; break; // Case map
        case 0x1E3A: out[0] = 0x1E3B; *count = 1; break; // Case map
        case 0x1E3C: out[0] = 0x1E3D; *count = 1; break; // Case map
        case 0x1E3E: out[0] = 0x1E3F; *count = 1; break; // Case map
        case 0x1E40: out[0] = 0x1E41; *count = 1; break; // Case map
        case 0x1E42: out[0] = 0x1E43; *count = 1; break; // Case map
        case 0x1E44: out[0] = 0x1E45; *count = 1; break; // Case map
        case 0x1E46: out[0] = 0x1E47; *count = 1; break; // Case map
        case 0x1E48: out[0] = 0x1E49; *count = 1; break; // Case map
        case 0x1E4A: out[0] = 0x1E4B; *count = 1; break; // Case map
        case 0x1E4C: out[0] = 0x1E4D; *count = 1; break; // Case map
        case 0x1E4E: out[0] = 0x1E4F; *count = 1; break; // Case map
        case 0x1E50: out[0] = 0x1E51; *count = 1; break; // Case map
        case 0x1E52: out[0] = 0x1E53; *count = 1; break; // Case map
        case 0x1E54: out[0] = 0x1E55; *count = 1; break; // Case map
        case 0x1E56: out[0] = 0x1E57; *count = 1; break; // Case map
        case 0x1E58: out[0] = 0x1E59; *count = 1; break; // Case map
        case 0x1E5A: out[0] = 0x1E5B; *count = 1; break; // Case map
        case 0x1E5C: out[0] = 0x1E5D; *count = 1; break; // Case map
        case 0x1E5E: out[0] = 0x1E5F; *count = 1; break; // Case map
        case 0x1E60: out[0] = 0x1E61; *count = 1; break; // Case map
        case 0x1E62: out[0] = 0x1E63; *count = 1; break; // Case map
        case 0x1E64: out[0] = 0x1E65; *count = 1; break; // Case map
        case 0x1E66: out[0] = 0x1E67; *count = 1; break; // Case map
        case 0x1E68: out[0] = 0x1E69; *count = 1; break; // Case map
        case 0x1E6A: out[0] = 0x1E6B; *count = 1; break; // Case map
        case 0x1E6C: out[0] = 0x1E6D; *count = 1; break; // Case map
        case 0x1E6E: out[0] = 0x1E6F; *count = 1; break; // Case map
        case 0x1E70: out[0] = 0x1E71; *count = 1; break; // Case map
        case 0x1E72: out[0] = 0x1E73; *count = 1; break; // Case map
        case 0x1E74: out[0] = 0x1E75; *count = 1; break; // Case map
        case 0x1E76: out[0] = 0x1E77; *count = 1; break; // Case map
        case 0x1E78: out[0] = 0x1E79; *count = 1; break; // Case map
        case 0x1E7A: out[0] = 0x1E7B; *count = 1; break; // Case map
        case 0x1E7C: out[0] = 0x1E7D; *count = 1; break; // Case map
        case 0x1E7E: out[0] = 0x1E7F; *count = 1; break; // Case map
        case 0x1E80: out[0] = 0x1E81; *count = 1; break; // Case map
        case 0x1E82: out[0] = 0x1E83; *count = 1; break; // Case map
        case 0x1E84: out[0] = 0x1E85; *count = 1; break; // Case map
        case 0x1E86: out[0] = 0x1E87; *count = 1; break; // Case map
        case 0x1E88: out[0] = 0x1E89; *count = 1; break; // Case map
        case 0x1E8A: out[0] = 0x1E8B; *count = 1; break; // Case map
        case 0x1E8C: out[0] = 0x1E8D; *count = 1; break; // Case map
        case 0x1E8E: out[0] = 0x1E8F; *count = 1; break; // Case map
        case 0x1E90: out[0] = 0x1E91; *count = 1; break; // Case map
        case 0x1E92: out[0] = 0x1E93; *count = 1; break; // Case map
        case 0x1E94: out[0] = 0x1E95; *count = 1; break; // Case map
        case 0x1E96: out[0] = 0x0068; out[1] = 0x0331; *count = 2; break; // Case map
        case 0x1E97: out[0] = 0x0074; out[1] = 0x0308; *count = 2; break; // Case map
        case 0x1E98: out[0] = 0x0077; out[1] = 0x030A; *count = 2; break; // Case map
        case 0x1E99: out[0] = 0x0079; out[1] = 0x030A; *count = 2; break; // Case map
        case 0x1E9A: out[0] = 0x0061; out[1] = 0x02BE; *count = 2; break; // Case map
        case 0x1E9B: out[0] = 0x1E61; *count = 1; break; // Case map
        case 0x1EA0: out[0] = 0x1EA1; *count = 1; break; // Case map
        case 0x1EA2: out[0] = 0x1EA3; *count = 1; break; // Case map
        case 0x1EA4: out[0] = 0x1EA5; *count = 1; break; // Case map
        case 0x1EA6: out[0] = 0x1EA7; *count = 1; break; // Case map
        case 0x1EA8: out[0] = 0x1EA9; *count = 1; break; // Case map
        case 0x1EAA: out[0] = 0x1EAB; *count = 1; break; // Case map
        case 0x1EAC: out[0] = 0x1EAD; *count = 1; break; // Case map
        case 0x1EAE: out[0] = 0x1EAF; *count = 1; break; // Case map
        case 0x1EB0: out[0] = 0x1EB1; *count = 1; break; // Case map
        case 0x1EB2: out[0] = 0x1EB3; *count = 1; break; // Case map
        case 0x1EB4: out[0] = 0x1EB5; *count = 1; break; // Case map
        case 0x1EB6: out[0] = 0x1EB7; *count = 1; break; // Case map
        case 0x1EB8: out[0] = 0x1EB9; *count = 1; break; // Case map
        case 0x1EBA: out[0] = 0x1EBB; *count = 1; break; // Case map
        case 0x1EBC: out[0] = 0x1EBD; *count = 1; break; // Case map
        case 0x1EBE: out[0] = 0x1EBF; *count = 1; break; // Case map
        case 0x1EC0: out[0] = 0x1EC1; *count = 1; break; // Case map
        case 0x1EC2: out[0] = 0x1EC3; *count = 1; break; // Case map
        case 0x1EC4: out[0] = 0x1EC5; *count = 1; break; // Case map
        case 0x1EC6: out[0] = 0x1EC7; *count = 1; break; // Case map
        case 0x1EC8: out[0] = 0x1EC9; *count = 1; break; // Case map
        case 0x1ECA: out[0] = 0x1ECB; *count = 1; break; // Case map
        case 0x1ECC: out[0] = 0x1ECD; *count = 1; break; // Case map
        case 0x1ECE: out[0] = 0x1ECF; *count = 1; break; // Case map
        case 0x1ED0: out[0] = 0x1ED1; *count = 1; break; // Case map
        case 0x1ED2: out[0] = 0x1ED3; *count = 1; break; // Case map
        case 0x1ED4: out[0] = 0x1ED5; *count = 1; break; // Case map
        case 0x1ED6: out[0] = 0x1ED7; *count = 1; break; // Case map
        case 0x1ED8: out[0] = 0x1ED9; *count = 1; break; // Case map
        case 0x1EDA: out[0] = 0x1EDB; *count = 1; break; // Case map
        case 0x1EDC: out[0] = 0x1EDD; *count = 1; break; // Case map
        case 0x1EDE: out[0] = 0x1EDF; *count = 1; break; // Case map
        case 0x1EE0: out[0] = 0x1EE1; *count = 1; break; // Case map
        case 0x1EE2: out[0] = 0x1EE3; *count = 1; break; // Case map
        case 0x1EE4: out[0] = 0x1EE5; *count = 1; break; // Case map
        case 0x1EE6: out[0] = 0x1EE7; *count = 1; break; // Case map
        case 0x1EE8: out[0] = 0x1EE9; *count = 1; break; // Case map
        case 0x1EEA: out[0] = 0x1EEB; *count = 1; break; // Case map
        case 0x1EEC: out[0] = 0x1EED; *count = 1; break; // Case map
        case 0x1EEE: out[0] = 0x1EEF; *count = 1; break; // Case map
        case 0x1EF0: out[0] = 0x1EF1; *count = 1; break; // Case map
        case 0x1EF2: out[0] = 0x1EF3; *count = 1; break; // Case map
        case 0x1EF4: out[0] = 0x1EF5; *count = 1; break; // Case map
        case 0x1EF6: out[0] = 0x1EF7; *count = 1; break; // Case map
        case 0x1EF8: out[0] = 0x1EF9; *count = 1; break; // Case map
        case 0x1F08: out[0] = 0x1F00; *count = 1; break; // Case map
        case 0x1F09: out[0] = 0x1F01; *count = 1; break; // Case map
        case 0x1F0A: out[0] = 0x1F02; *count = 1; break; // Case map
        case 0x1F0B: out[0] = 0x1F03; *count = 1; break; // Case map
        case 0x1F0C: out[0] = 0x1F04; *count = 1; break; // Case map
        case 0x1F0D: out[0] = 0x1F05; *count = 1; break; // Case map
        case 0x1F0E: out[0] = 0x1F06; *count = 1; break; // Case map
        case 0x1F0F: out[0] = 0x1F07; *count = 1; break; // Case map
        case 0x1F18: out[0] = 0x1F10; *count = 1; break; // Case map
        case 0x1F19: out[0] = 0x1F11; *count = 1; break; // Case map
        case 0x1F1A: out[0] = 0x1F12; *count = 1; break; // Case map
        case 0x1F1B: out[0] = 0x1F13; *count = 1; break; // Case map
        case 0x1F1C: out[0] = 0x1F14; *count = 1; break; // Case map
        case 0x1F1D: out[0] = 0x1F15; *count = 1; break; // Case map
        case 0x1F28: out[0] = 0x1F20; *count = 1; break; // Case map
        case 0x1F29: out[0] = 0x1F21; *count = 1; break; // Case map
        case 0x1F2A: out[0] = 0x1F22; *count = 1; break; // Case map
        case 0x1F2B: out[0] = 0x1F23; *count = 1; break; // Case map
        case 0x1F2C: out[0] = 0x1F24; *count = 1; break; // Case map
        case 0x1F2D: out[0] = 0x1F25; *count = 1; break; // Case map
        case 0x1F2E: out[0] = 0x1F26; *count = 1; break; // Case map
        case 0x1F2F: out[0] = 0x1F27; *count = 1; break; // Case map
        case 0x1F38: out[0] = 0x1F30; *count = 1; break; // Case map
        case 0x1F39: out[0] = 0x1F31; *count = 1; break; // Case map
        case 0x1F3A: out[0] = 0x1F32; *count = 1; break; // Case map
        case 0x1F3B: out[0] = 0x1F33; *count = 1; break; // Case map
        case 0x1F3C: out[0] = 0x1F34; *count = 1; break; // Case map
        case 0x1F3D: out[0] = 0x1F35; *count = 1; break; // Case map
        case 0x1F3E: out[0] = 0x1F36; *count = 1; break; // Case map
        case 0x1F3F: out[0] = 0x1F37; *count = 1; break; // Case map
        case 0x1F48: out[0] = 0x1F40; *count = 1; break; // Case map
        case 0x1F49: out[0] = 0x1F41; *count = 1; break; // Case map
        case 0x1F4A: out[0] = 0x1F42; *count = 1; break; // Case map
        case 0x1F4B: out[0] = 0x1F43; *count = 1; break; // Case map
        case 0x1F4C: out[0] = 0x1F44; *count = 1; break; // Case map
        case 0x1F4D: out[0] = 0x1F45; *count = 1; break; // Case map
        case 0x1F50: out[0] = 0x03C5; out[1] = 0x0313; *count = 2; break; // Case map
        case 0x1F52: out[0] = 0x03C5; out[1] = 0x0313; out[2] = 0x0300; *count = 3; break; // Case map
        case 0x1F54: out[0] = 0x03C5; out[1] = 0x0313; out[2] = 0x0301; *count = 3; break; // Case map
        case 0x1F56: out[0] = 0x03C5; out[1] = 0x0313; out[2] = 0x0342; *count = 3; break; // Case map
        case 0x1F59: out[0] = 0x1F51; *count = 1; break; // Case map
        case 0x1F5B: out[0] = 0x1F53; *count = 1; break; // Case map
        case 0x1F5D: out[0] = 0x1F55; *count = 1; break; // Case map
        case 0x1F5F: out[0] = 0x1F57; *count = 1; break; // Case map
        case 0x1F68: out[0] = 0x1F60; *count = 1; break; // Case map
        case 0x1F69: out[0] = 0x1F61; *count = 1; break; // Case map
        case 0x1F6A: out[0] = 0x1F62; *count = 1; break; // Case map
        case 0x1F6B: out[0] = 0x1F63; *count = 1; break; // Case map
        case 0x1F6C: out[0] = 0x1F64; *count = 1; break; // Case map
        case 0x1F6D: out[0] = 0x1F65; *count = 1; break; // Case map
        case 0x1F6E: out[0] = 0x1F66; *count = 1; break; // Case map
        case 0x1F6F: out[0] = 0x1F67; *count = 1; break; // Case map
        case 0x1F80: out[0] = 0x1F00; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F81: out[0] = 0x1F01; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F82: out[0] = 0x1F02; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F83: out[0] = 0x1F03; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F84: out[0] = 0x1F04; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F85: out[0] = 0x1F05; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F86: out[0] = 0x1F06; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F87: out[0] = 0x1F07; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F88: out[0] = 0x1F00; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F89: out[0] = 0x1F01; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F8A: out[0] = 0x1F02; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F8B: out[0] = 0x1F03; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F8C: out[0] = 0x1F04; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F8D: out[0] = 0x1F05; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F8E: out[0] = 0x1F06; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F8F: out[0] = 0x1F07; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F90: out[0] = 0x1F20; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F91: out[0] = 0x1F21; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F92: out[0] = 0x1F22; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F93: out[0] = 0x1F23; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F94: out[0] = 0x1F24; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F95: out[0] = 0x1F25; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F96: out[0] = 0x1F26; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F97: out[0] = 0x1F27; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F98: out[0] = 0x1F20; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F99: out[0] = 0x1F21; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F9A: out[0] = 0x1F22; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F9B: out[0] = 0x1F23; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F9C: out[0] = 0x1F24; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F9D: out[0] = 0x1F25; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F9E: out[0] = 0x1F26; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1F9F: out[0] = 0x1F27; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FA0: out[0] = 0x1F60; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FA1: out[0] = 0x1F61; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FA2: out[0] = 0x1F62; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FA3: out[0] = 0x1F63; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FA4: out[0] = 0x1F64; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FA5: out[0] = 0x1F65; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FA6: out[0] = 0x1F66; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FA7: out[0] = 0x1F67; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FA8: out[0] = 0x1F60; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FA9: out[0] = 0x1F61; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FAA: out[0] = 0x1F62; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FAB: out[0] = 0x1F63; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FAC: out[0] = 0x1F64; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FAD: out[0] = 0x1F65; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FAE: out[0] = 0x1F66; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FAF: out[0] = 0x1F67; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FB2: out[0] = 0x1F70; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FB3: out[0] = 0x03B1; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FB4: out[0] = 0x03AC; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FB6: out[0] = 0x03B1; out[1] = 0x0342; *count = 2; break; // Case map
        case 0x1FB7: out[0] = 0x03B1; out[1] = 0x0342; out[2] = 0x03B9; *count = 3; break; // Case map
        case 0x1FB8: out[0] = 0x1FB0; *count = 1; break; // Case map
        case 0x1FB9: out[0] = 0x1FB1; *count = 1; break; // Case map
        case 0x1FBA: out[0] = 0x1F70; *count = 1; break; // Case map
        case 0x1FBB: out[0] = 0x1F71; *count = 1; break; // Case map
        case 0x1FBC: out[0] = 0x03B1; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FBE: out[0] = 0x03B9; *count = 1; break; // Case map
        case 0x1FC2: out[0] = 0x1F74; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FC3: out[0] = 0x03B7; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FC4: out[0] = 0x03AE; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FC6: out[0] = 0x03B7; out[1] = 0x0342; *count = 2; break; // Case map
        case 0x1FC7: out[0] = 0x03B7; out[1] = 0x0342; out[2] = 0x03B9; *count = 3; break; // Case map
        case 0x1FC8: out[0] = 0x1F72; *count = 1; break; // Case map
        case 0x1FC9: out[0] = 0x1F73; *count = 1; break; // Case map
        case 0x1FCA: out[0] = 0x1F74; *count = 1; break; // Case map
        case 0x1FCB: out[0] = 0x1F75; *count = 1; break; // Case map
        case 0x1FCC: out[0] = 0x03B7; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FD2: out[0] = 0x03B9; out[1] = 0x0308; out[2] = 0x0300; *count = 3; break; // Case map
        case 0x1FD3: out[0] = 0x03B9; out[1] = 0x0308; out[2] = 0x0301; *count = 3; break; // Case map
        case 0x1FD6: out[0] = 0x03B9; out[1] = 0x0342; *count = 2; break; // Case map
        case 0x1FD7: out[0] = 0x03B9; out[1] = 0x0308; out[2] = 0x0342; *count = 3; break; // Case map
        case 0x1FD8: out[0] = 0x1FD0; *count = 1; break; // Case map
        case 0x1FD9: out[0] = 0x1FD1; *count = 1; break; // Case map
        case 0x1FDA: out[0] = 0x1F76; *count = 1; break; // Case map
        case 0x1FDB: out[0] = 0x1F77; *count = 1; break; // Case map
        case 0x1FE2: out[0] = 0x03C5; out[1] = 0x0308; out[2] = 0x0300; *count = 3; break; // Case map
        case 0x1FE3: out[0] = 0x03C5; out[1] = 0x0308; out[2] = 0x0301; *count = 3; break; // Case map
        case 0x1FE4: out[0] = 0x03C1; out[1] = 0x0313; *count = 2; break; // Case map
        case 0x1FE6: out[0] = 0x03C5; out[1] = 0x0342; *count = 2; break; // Case map
        case 0x1FE7: out[0] = 0x03C5; out[1] = 0x0308; out[2] = 0x0342; *count = 3; break; // Case map
        case 0x1FE8: out[0] = 0x1FE0; *count = 1; break; // Case map
        case 0x1FE9: out[0] = 0x1FE1; *count = 1; break; // Case map
        case 0x1FEA: out[0] = 0x1F7A; *count = 1; break; // Case map
        case 0x1FEB: out[0] = 0x1F7B; *count = 1; break; // Case map
        case 0x1FEC: out[0] = 0x1FE5; *count = 1; break; // Case map
        case 0x1FF2: out[0] = 0x1F7C; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FF3: out[0] = 0x03C9; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FF4: out[0] = 0x03CE; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x1FF6: out[0] = 0x03C9; out[1] = 0x0342; *count = 2; break; // Case map
        case 0x1FF7: out[0] = 0x03C9; out[1] = 0x0342; out[2] = 0x03B9; *count = 3; break; // Case map
        case 0x1FF8: out[0] = 0x1F78; *count = 1; break; // Case map
        case 0x1FF9: out[0] = 0x1F79; *count = 1; break; // Case map
        case 0x1FFA: out[0] = 0x1F7C; *count = 1; break; // Case map
        case 0x1FFB: out[0] = 0x1F7D; *count = 1; break; // Case map
        case 0x1FFC: out[0] = 0x03C9; out[1] = 0x03B9; *count = 2; break; // Case map
        case 0x20A8: out[0] = 0x0072; out[1] = 0x0073; *count = 2; break; // Additional folding
        case 0x2102: out[0] = 0x0063; *count = 1; break; // Additional folding
        case 0x2103: out[0] = 0x00B0; out[1] = 0x0063; *count = 2; break; // Additional folding
        case 0x2107: out[0] = 0x025B; *count = 1; break; // Additional folding
        case 0x2109: out[0] = 0x00B0; out[1] = 0x0066; *count = 2; break; // Additional folding
        case 0x210B: out[0] = 0x0068; *count = 1; break; // Additional folding
        case 0x210C: out[0] = 0x0068; *count = 1; break; // Additional folding
        case 0x210D: out[0] = 0x0068; *count = 1; break; // Additional folding
        case 0x2110: out[0] = 0x0069; *count = 1; break; // Additional folding
        case 0x2111: out[0] = 0x0069; *count = 1; break; // Additional folding
        case 0x2112: out[0] = 0x006C; *count = 1; break; // Additional folding
        case 0x2115: out[0] = 0x006E; *count = 1; break; // Additional folding
        case 0x2116: out[0] = 0x006E; out[1] = 0x006F; *count = 2; break; // Additional folding
        case 0x2119: out[0] = 0x0070; *count = 1; break; // Additional folding
        case 0x211A: out[0] = 0x0071; *count = 1; break; // Additional folding
        case 0x211B: out[0] = 0x0072; *count = 1; break; // Additional folding
        case 0x211C: out[0] = 0x0072; *count = 1; break; // Additional folding
        case 0x211D: out[0] = 0x0072; *count = 1; break; // Additional folding
        case 0x2120: out[0] = 0x0073; out[1] = 0x006D; *count = 2; break; // Additional folding
        case 0x2121: out[0] = 0x0074; out[1] = 0x0065; out[2] = 0x006C; *count = 3; break; // Additional folding
        case 0x2122: out[0] = 0x0074; out[1] = 0x006D; *count = 2; break; // Additional folding
        case 0x2124: out[0] = 0x007A; *count = 1; break; // Additional folding
        case 0x2126: out[0] = 0x03C9; *count = 1; break; // Case map
        case 0x2128: out[0] = 0x007A; *count = 1; break; // Additional folding
        case 0x212A: out[0] = 0x006B; *count = 1; break; // Case map
        case 0x212B: out[0] = 0x00E5; *count = 1; break; // Case map
        case 0x212C: out[0] = 0x0062; *count = 1; break; // Additional folding
        case 0x212D: out[0] = 0x0063; *count = 1; break; // Additional folding
        case 0x2130: out[0] = 0x0065; *count = 1; break; // Additional folding
        case 0x2131: out[0] = 0x0066; *count = 1; break; // Additional folding
        case 0x2133: out[0] = 0x006D; *count = 1; break; // Additional folding
        case 0x213E: out[0] = 0x03B3; *count = 1; break; // Additional folding
        case 0x213F: out[0] = 0x03C0; *count = 1; break; // Additional folding
        case 0x2145: out[0] = 0x0064; *count = 1; break; // Additional folding
        case 0x2160: out[0] = 0x2170; *count = 1; break; // Case map
        case 0x2161: out[0] = 0x2171; *count = 1; break; // Case map
        case 0x2162: out[0] = 0x2172; *count = 1; break; // Case map
        case 0x2163: out[0] = 0x2173; *count = 1; break; // Case map
        case 0x2164: out[0] = 0x2174; *count = 1; break; // Case map
        case 0x2165: out[0] = 0x2175; *count = 1; break; // Case map
        case 0x2166: out[0] = 0x2176; *count = 1; break; // Case map
        case 0x2167: out[0] = 0x2177; *count = 1; break; // Case map
        case 0x2168: out[0] = 0x2178; *count = 1; break; // Case map
        case 0x2169: out[0] = 0x2179; *count = 1; break; // Case map
        case 0x216A: out[0] = 0x217A; *count = 1; break; // Case map
        case 0x216B: out[0] = 0x217B; *count = 1; break; // Case map
        case 0x216C: out[0] = 0x217C; *count = 1; break; // Case map
        case 0x216D: out[0] = 0x217D; *count = 1; break; // Case map
        case 0x216E: out[0] = 0x217E; *count = 1; break; // Case map
        case 0x216F: out[0] = 0x217F; *count = 1; break; // Case map
        case 0x24B6: out[0] = 0x24D0; *count = 1; break; // Case map
        case 0x24B7: out[0] = 0x24D1; *count = 1; break; // Case map
        case 0x24B8: out[0] = 0x24D2; *count = 1; break; // Case map
        case 0x24B9: out[0] = 0x24D3; *count = 1; break; // Case map
        case 0x24BA: out[0] = 0x24D4; *count = 1; break; // Case map
        case 0x24BB: out[0] = 0x24D5; *count = 1; break; // Case map
        case 0x24BC: out[0] = 0x24D6; *count = 1; break; // Case map
        case 0x24BD: out[0] = 0x24D7; *count = 1; break; // Case map
        case 0x24BE: out[0] = 0x24D8; *count = 1; break; // Case map
        case 0x24BF: out[0] = 0x24D9; *count = 1; break; // Case map
        case 0x24C0: out[0] = 0x24DA; *count = 1; break; // Case map
        case 0x24C1: out[0] = 0x24DB; *count = 1; break; // Case map
        case 0x24C2: out[0] = 0x24DC; *count = 1; break; // Case map
        case 0x24C3: out[0] = 0x24DD; *count = 1; break; // Case map
        case 0x24C4: out[0] = 0x24DE; *count = 1; break; // Case map
        case 0x24C5: out[0] = 0x24DF; *count = 1; break; // Case map
        case 0x24C6: out[0] = 0x24E0; *count = 1; break; // Case map
        case 0x24C7: out[0] = 0x24E1; *count = 1; break; // Case map
        case 0x24C8: out[0] = 0x24E2; *count = 1; break; // Case map
        case 0x24C9: out[0] = 0x24E3; *count = 1; break; // Case map
        case 0x24CA: out[0] = 0x24E4; *count = 1; break; // Case map
        case 0x24CB: out[0] = 0x24E5; *count = 1; break; // Case map
        case 0x24CC: out[0] = 0x24E6; *count = 1; break; // Case map
        case 0x24CD: out[0] = 0x24E7; *count = 1; break; // Case map
        case 0x24CE: out[0] = 0x24E8; *count = 1; break; // Case map
        case 0x24CF: out[0] = 0x24E9; *count = 1; break; // Case map
        case 0x3371: out[0] = 0x0068; out[1] = 0x0070; out[2] = 0x0061; *count = 3; break; // Additional folding
        case 0x3373: out[0] = 0x0061; out[1] = 0x0075; *count = 2; break; // Additional folding
        case 0x3375: out[0] = 0x006F; out[1] = 0x0076; *count = 2; break; // Additional folding
        case 0x3380: out[0] = 0x0070; out[1] = 0x0061; *count = 2; break; // Additional folding
        case 0x3381: out[0] = 0x006E; out[1] = 0x0061; *count = 2; break; // Additional folding
        case 0x3382: out[0] = 0x03BC; out[1] = 0x0061; *count = 2; break; // Additional folding
        case 0x3383: out[0] = 0x006D; out[1] = 0x0061; *count = 2; break; // Additional folding
        case 0x3384: out[0] = 0x006B; out[1] = 0x0061; *count = 2; break; // Additional folding
        case 0x3385: out[0] = 0x006B; out[1] = 0x0062; *count = 2; break; // Additional folding
        case 0x3386: out[0] = 0x006D; out[1] = 0x0062; *count = 2; break; // Additional folding
        case 0x3387: out[0] = 0x0067; out[1] = 0x0062; *count = 2; break; // Additional folding
        case 0x338A: out[0] = 0x0070; out[1] = 0x0066; *count = 2; break; // Additional folding
        case 0x338B: out[0] = 0x006E; out[1] = 0x0066; *count = 2; break; // Additional folding
        case 0x338C: out[0] = 0x03BC; out[1] = 0x0066; *count = 2; break; // Additional folding
        case 0x3390: out[0] = 0x0068; out[1] = 0x007A; *count = 2; break; // Additional folding
        case 0x3391: out[0] = 0x006B; out[1] = 0x0068; out[2] = 0x007A; *count = 3; break; // Additional folding
        case 0x3392: out[0] = 0x006D; out[1] = 0x0068; out[2] = 0x007A; *count = 3; break; // Additional folding
        case 0x3393: out[0] = 0x0067; out[1] = 0x0068; out[2] = 0x007A; *count = 3; break; // Additional folding
        case 0x3394: out[0] = 0x0074; out[1] = 0x0068; out[2] = 0x007A; *count = 3; break; // Additional folding
        case 0x33A9: out[0] = 0x0070; out[1] = 0x0061; *count = 2; break; // Additional folding
        case 0x33AA: out[0] = 0x006B; out[1] = 0x0070; out[2] = 0x0061; *count = 3; break; // Additional folding
        case 0x33AB: out[0] = 0x006D; out[1] = 0x0070; out[2] = 0x0061; *count = 3; break; // Additional folding
        case 0x33AC: out[0] = 0x0067; out[1] = 0x0070; out[2] = 0x0061; *count = 3; break; // Additional folding
        case 0x33B4: out[0] = 0x0070; out[1] = 0x0076; *count = 2; break; // Additional folding
        case 0x33B5: out[0] = 0x006E; out[1] = 0x0076; *count = 2; break; // Additional folding
        case 0x33B6: out[0] = 0x03BC; out[1] = 0x0076; *count = 2; break; // Additional folding
        case 0x33B7: out[0] = 0x006D; out[1] = 0x0076; *count = 2; break; // Additional folding
        case 0x33B8: out[0] = 0x006B; out[1] = 0x0076; *count = 2; break; // Additional folding
        case 0x33B9: out[0] = 0x006D; out[1] = 0x0076; *count = 2; break; // Additional folding
        case 0x33BA: out[0] = 0x0070; out[1] = 0x0077; *count = 2; break; // Additional folding
        case 0x33BB: out[0] = 0x006E; out[1] = 0x0077; *count = 2; break; // Additional folding
        case 0x33BC: out[0] = 0x03BC; out[1] = 0x0077; *count = 2; break; // Additional folding
        case 0x33BD: out[0] = 0x006D; out[1] = 0x0077; *count = 2; break; // Additional folding
        case 0x33BE: out[0] = 0x006B; out[1] = 0x0077; *count = 2; break; // Additional folding
        case 0x33BF: out[0] = 0x006D; out[1] = 0x0077; *count = 2; break; // Additional folding
        case 0x33C0: out[0] = 0x006B; out[1] = 0x03C9; *count = 2; break; // Additional folding
        case 0x33C1: out[0] = 0x006D; out[1] = 0x03C9; *count = 2; break; // Additional folding
        case 0x33C3: out[0] = 0x0062; out[1] = 0x0071; *count = 2; break; // Additional folding
        case 0x33C6: out[0] = 0x0063; out[1] = 0x2215; out[2] = 0x006B; out[3] = 0x0067; *count = 4; break; // Additional folding
        case 0x33C7: out[0] = 0x0063; out[1] = 0x006F; out[2] = 0x002E; *count = 3; break; // Additional folding
        case 0x33C8: out[0] = 0x0064; out[1] = 0x0062; *count = 2; break; // Additional folding
        case 0x33C9: out[0] = 0x0067; out[1] = 0x0079; *count = 2; break; // Additional folding
        case 0x33CB: out[0] = 0x0068; out[1] = 0x0070; *count = 2; break; // Additional folding
        case 0x33CD: out[0] = 0x006B; out[1] = 0x006B; *count = 2; break; // Additional folding
        case 0x33CE: out[0] = 0x006B; out[1] = 0x006D; *count = 2; break; // Additional folding
        case 0x33D7: out[0] = 0x0070; out[1] = 0x0068; *count = 2; break; // Additional folding
        case 0x33D9: out[0] = 0x0070; out[1] = 0x0070; out[2] = 0x006D; *count = 3; break; // Additional folding
        case 0x33DA: out[0] = 0x0070; out[1] = 0x0072; *count = 2; break; // Additional folding
        case 0x33DC: out[0] = 0x0073; out[1] = 0x0076; *count = 2; break; // Additional folding
        case 0x33DD: out[0] = 0x0077; out[1] = 0x0062; *count = 2; break; // Additional folding
        case 0xFB00: out[0] = 0x0066; out[1] = 0x0066; *count = 2; break; // Case map
        case 0xFB01: out[0] = 0x0066; out[1] = 0x0069; *count = 2; break; // Case map
        case 0xFB02: out[0] = 0x0066; out[1] = 0x006C; *count = 2; break; // Case map
        case 0xFB03: out[0] = 0x0066; out[1] = 0x0066; out[2] = 0x0069; *count = 3; break; // Case map
        case 0xFB04: out[0] = 0x0066; out[1] = 0x0066; out[2] = 0x006C; *count = 3; break; // Case map
        case 0xFB05: out[0] = 0x0073; out[1] = 0x0074; *count = 2; break; // Case map
        case 0xFB06: out[0] = 0x0073; out[1] = 0x0074; *count = 2; break; // Case map
        case 0xFB13: out[0] = 0x0574; out[1] = 0x0576; *count = 2; break; // Case map
        case 0xFB14: out[0] = 0x0574; out[1] = 0x0565; *count = 2; break; // Case map
        case 0xFB15: out[0] = 0x0574; out[1] = 0x056B; *count = 2; break; // Case map
        case 0xFB16: out[0] = 0x057E; out[1] = 0x0576; *count = 2; break; // Case map
        case 0xFB17: out[0] = 0x0574; out[1] = 0x056D; *count = 2; break; // Case map
        case 0xFF21: out[0] = 0xFF41; *count = 1; break; // Case map
        case 0xFF22: out[0] = 0xFF42; *count = 1; break; // Case map
        case 0xFF23: out[0] = 0xFF43; *count = 1; break; // Case map
        case 0xFF24: out[0] = 0xFF44; *count = 1; break; // Case map
        case 0xFF25: out[0] = 0xFF45; *count = 1; break; // Case map
        case 0xFF26: out[0] = 0xFF46; *count = 1; break; // Case map
        case 0xFF27: out[0] = 0xFF47; *count = 1; break; // Case map
        case 0xFF28: out[0] = 0xFF48; *count = 1; break; // Case map
        case 0xFF29: out[0] = 0xFF49; *count = 1; break; // Case map
        case 0xFF2A: out[0] = 0xFF4A; *count = 1; break; // Case map
        case 0xFF2B: out[0] = 0xFF4B; *count = 1; break; // Case map
        case 0xFF2C: out[0] = 0xFF4C; *count = 1; break; // Case map
        case 0xFF2D: out[0] = 0xFF4D; *count = 1; break; // Case map
        case 0xFF2E: out[0] = 0xFF4E; *count = 1; break; // Case map
        case 0xFF2F: out[0] = 0xFF4F; *count = 1; break; // Case map
        case 0xFF30: out[0] = 0xFF50; *count = 1; break; // Case map
        case 0xFF31: out[0] = 0xFF51; *count = 1; break; // Case map
        case 0xFF32: out[0] = 0xFF52; *count = 1; break; // Case map
        case 0xFF33: out[0] = 0xFF53; *count = 1; break; // Case map
        case 0xFF34: out[0] = 0xFF54; *count = 1; break; // Case map
        case 0xFF35: out[0] = 0xFF55; *count = 1; break; // Case map
        case 0xFF36: out[0] = 0xFF56; *count = 1; break; // Case map
        case 0xFF37: out[0] = 0xFF57; *count = 1; break; // Case map
        case 0xFF38: out[0] = 0xFF58; *count = 1; break; // Case map
        case 0xFF39: out[0] = 0xFF59; *count = 1; break; // Case map
        case 0xFF3A: out[0] = 0xFF5A; *count = 1; break; // Case map
        case 0x10400: out[0] = 0x10428; *count = 1; break; // Case map
        case 0x10401: out[0] = 0x10429; *count = 1; break; // Case map
        case 0x10402: out[0] = 0x1042A; *count = 1; break; // Case map
        case 0x10403: out[0] = 0x1042B; *count = 1; break; // Case map
        case 0x10404: out[0] = 0x1042C; *count = 1; break; // Case map
        case 0x10405: out[0] = 0x1042D; *count = 1; break; // Case map
        case 0x10406: out[0] = 0x1042E; *count = 1; break; // Case map
        case 0x10407: out[0] = 0x1042F; *count = 1; break; // Case map
        case 0x10408: out[0] = 0x10430; *count = 1; break; // Case map
        case 0x10409: out[0] = 0x10431; *count = 1; break; // Case map
        case 0x1040A: out[0] = 0x10432; *count = 1; break; // Case map
        case 0x1040B: out[0] = 0x10433; *count = 1; break; // Case map
        case 0x1040C: out[0] = 0x10434; *count = 1; break; // Case map
        case 0x1040D: out[0] = 0x10435; *count = 1; break; // Case map
        case 0x1040E: out[0] = 0x10436; *count = 1; break; // Case map
        case 0x1040F: out[0] = 0x10437; *count = 1; break; // Case map
        case 0x10410: out[0] = 0x10438; *count = 1; break; // Case map
        case 0x10411: out[0] = 0x10439; *count = 1; break; // Case map
        case 0x10412: out[0] = 0x1043A; *count = 1; break; // Case map
        case 0x10413: out[0] = 0x1043B; *count = 1; break; // Case map
        case 0x10414: out[0] = 0x1043C; *count = 1; break; // Case map
        case 0x10415: out[0] = 0x1043D; *count = 1; break; // Case map
        case 0x10416: out[0] = 0x1043E; *count = 1; break; // Case map
        case 0x10417: out[0] = 0x1043F; *count = 1; break; // Case map
        case 0x10418: out[0] = 0x10440; *count = 1; break; // Case map
        case 0x10419: out[0] = 0x10441; *count = 1; break; // Case map
        case 0x1041A: out[0] = 0x10442; *count = 1; break; // Case map
        case 0x1041B: out[0] = 0x10443; *count = 1; break; // Case map
        case 0x1041C: out[0] = 0x10444; *count = 1; break; // Case map
        case 0x1041D: out[0] = 0x10445; *count = 1; break; // Case map
        case 0x1041E: out[0] = 0x10446; *count = 1; break; // Case map
        case 0x1041F: out[0] = 0x10447; *count = 1; break; // Case map
        case 0x10420: out[0] = 0x10448; *count = 1; break; // Case map
        case 0x10421: out[0] = 0x10449; *count = 1; break; // Case map
        case 0x10422: out[0] = 0x1044A; *count = 1; break; // Case map
        case 0x10423: out[0] = 0x1044B; *count = 1; break; // Case map
        case 0x10424: out[0] = 0x1044C; *count = 1; break; // Case map
        case 0x10425: out[0] = 0x1044D; *count = 1; break; // Case map
        case 0x1D400: out[0] = 0x0061; *count = 1; break; // Additional folding
        case 0x1D401: out[0] = 0x0062; *count = 1; break; // Additional folding
        case 0x1D402: out[0] = 0x0063; *count = 1; break; // Additional folding
        case 0x1D403: out[0] = 0x0064; *count = 1; break; // Additional folding
        case 0x1D404: out[0] = 0x0065; *count = 1; break; // Additional folding
        case 0x1D405: out[0] = 0x0066; *count = 1; break; // Additional folding
        case 0x1D406: out[0] = 0x0067; *count = 1; break; // Additional folding
        case 0x1D407: out[0] = 0x0068; *count = 1; break; // Additional folding
        case 0x1D408: out[0] = 0x0069; *count = 1; break; // Additional folding
        case 0x1D409: out[0] = 0x006A; *count = 1; break; // Additional folding
        case 0x1D40A: out[0] = 0x006B; *count = 1; break; // Additional folding
        case 0x1D40B: out[0] = 0x006C; *count = 1; break; // Additional folding
        case 0x1D40C: out[0] = 0x006D; *count = 1; break; // Additional folding
        case 0x1D40D: out[0] = 0x006E; *count = 1; break; // Additional folding
        case 0x1D40E: out[0] = 0x006F; *count = 1; break; // Additional folding
        case 0x1D40F: out[0] = 0x0070; *count = 1; break; // Additional folding
        case 0x1D410: out[0] = 0x0071; *count = 1; break; // Additional folding
        case 0x1D411: out[0] = 0x0072; *count = 1; break; // Additional folding
        case 0x1D412: out[0] = 0x0073; *count = 1; break; // Additional folding
        case 0x1D413: out[0] = 0x0074; *count = 1; break; // Additional folding
        case 0x1D414: out[0] = 0x0075; *count = 1; break; // Additional folding
        case 0x1D415: out[0] = 0x0076; *count = 1; break; // Additional folding
        case 0x1D416: out[0] = 0x0077; *count = 1; break; // Additional folding
        case 0x1D417: out[0] = 0x0078; *count = 1; break; // Additional folding
        case 0x1D418: out[0] = 0x0079; *count = 1; break; // Additional folding
        case 0x1D419: out[0] = 0x007A; *count = 1; break; // Additional folding
        case 0x1D434: out[0] = 0x0061; *count = 1; break; // Additional folding
        case 0x1D435: out[0] = 0x0062; *count = 1; break; // Additional folding
        case 0x1D436: out[0] = 0x0063; *count = 1; break; // Additional folding
        case 0x1D437: out[0] = 0x0064; *count = 1; break; // Additional folding
        case 0x1D438: out[0] = 0x0065; *count = 1; break; // Additional folding
        case 0x1D439: out[0] = 0x0066; *count = 1; break; // Additional folding
        case 0x1D43A: out[0] = 0x0067; *count = 1; break; // Additional folding
        case 0x1D43B: out[0] = 0x0068; *count = 1; break; // Additional folding
        case 0x1D43C: out[0] = 0x0069; *count = 1; break; // Additional folding
        case 0x1D43D: out[0] = 0x006A; *count = 1; break; // Additional folding
        case 0x1D43E: out[0] = 0x006B; *count = 1; break; // Additional folding
        case 0x1D43F: out[0] = 0x006C; *count = 1; break; // Additional folding
        case 0x1D440: out[0] = 0x006D; *count = 1; break; // Additional folding
        case 0x1D441: out[0] = 0x006E; *count = 1; break; // Additional folding
        case 0x1D442: out[0] = 0x006F; *count = 1; break; // Additional folding
        case 0x1D443: out[0] = 0x0070; *count = 1; break; // Additional folding
        case 0x1D444: out[0] = 0x0071; *count = 1; break; // Additional folding
        case 0x1D445: out[0] = 0x0072; *count = 1; break; // Additional folding
        case 0x1D446: out[0] = 0x0073; *count = 1; break; // Additional folding
        case 0x1D447: out[0] = 0x0074; *count = 1; break; // Additional folding
        case 0x1D448: out[0] = 0x0075; *count = 1; break; // Additional folding
        case 0x1D449: out[0] = 0x0076; *count = 1; break; // Additional folding
        case 0x1D44A: out[0] = 0x0077; *count = 1; break; // Additional folding
        case 0x1D44B: out[0] = 0x0078; *count = 1; break; // Additional folding
        case 0x1D44C: out[0] = 0x0079; *count = 1; break; // Additional folding
        case 0x1D44D: out[0] = 0x007A; *count = 1; break; // Additional folding
        case 0x1D468: out[0] = 0x0061; *count = 1; break; // Additional folding
        case 0x1D469: out[0] = 0x0062; *count = 1; break; // Additional folding
        case 0x1D46A: out[0] = 0x0063; *count = 1; break; // Additional folding
        case 0x1D46B: out[0] = 0x0064; *count = 1; break; // Additional folding
        case 0x1D46C: out[0] = 0x0065; *count = 1; break; // Additional folding
        case 0x1D46D: out[0] = 0x0066; *count = 1; break; // Additional folding
        case 0x1D46E: out[0] = 0x0067; *count = 1; break; // Additional folding
        case 0x1D46F: out[0] = 0x0068; *count = 1; break; // Additional folding
        case 0x1D470: out[0] = 0x0069; *count = 1; break; // Additional folding
        case 0x1D471: out[0] = 0x006A; *count = 1; break; // Additional folding
        case 0x1D472: out[0] = 0x006B; *count = 1; break; // Additional folding
        case 0x1D473: out[0] = 0x006C; *count = 1; break; // Additional folding
        case 0x1D474: out[0] = 0x006D; *count = 1; break; // Additional folding
        case 0x1D475: out[0] = 0x006E; *count = 1; break; // Additional folding
        case 0x1D476: out[0] = 0x006F; *count = 1; break; // Additional folding
        case 0x1D477: out[0] = 0x0070; *count = 1; break; // Additional folding
        case 0x1D478: out[0] = 0x0071; *count = 1; break; // Additional folding
        case 0x1D479: out[0] = 0x0072; *count = 1; break; // Additional folding
        case 0x1D47A: out[0] = 0x0073; *count = 1; break; // Additional folding
        case 0x1D47B: out[0] = 0x0074; *count = 1; break; // Additional folding
        case 0x1D47C: out[0] = 0x0075; *count = 1; break; // Additional folding
        case 0x1D47D: out[0] = 0x0076; *count = 1; break; // Additional folding
        case 0x1D47E: out[0] = 0x0077; *count = 1; break; // Additional folding
        case 0x1D47F: out[0] = 0x0078; *count = 1; break; // Additional folding
        case 0x1D480: out[0] = 0x0079; *count = 1; break; // Additional folding
        case 0x1D481: out[0] = 0x007A; *count = 1; break; // Additional folding
        case 0x1D49C: out[0] = 0x0061; *count = 1; break; // Additional folding
        case 0x1D49E: out[0] = 0x0063; *count = 1; break; // Additional folding
        case 0x1D49F: out[0] = 0x0064; *count = 1; break; // Additional folding
        case 0x1D4A2: out[0] = 0x0067; *count = 1; break; // Additional folding
        case 0x1D4A5: out[0] = 0x006A; *count = 1; break; // Additional folding
        case 0x1D4A6: out[0] = 0x006B; *count = 1; break; // Additional folding
        case 0x1D4A9: out[0] = 0x006E; *count = 1; break; // Additional folding
        case 0x1D4AA: out[0] = 0x006F; *count = 1; break; // Additional folding
        case 0x1D4AB: out[0] = 0x0070; *count = 1; break; // Additional folding
        case 0x1D4AC: out[0] = 0x0071; *count = 1; break; // Additional folding
        case 0x1D4AE: out[0] = 0x0073; *count = 1; break; // Additional folding
        case 0x1D4AF: out[0] = 0x0074; *count = 1; break; // Additional folding
        case 0x1D4B0: out[0] = 0x0075; *count = 1; break; // Additional folding
        case 0x1D4B1: out[0] = 0x0076; *count = 1; break; // Additional folding
        case 0x1D4B2: out[0] = 0x0077; *count = 1; break; // Additional folding
        case 0x1D4B3: out[0] = 0x0078; *count = 1; break; // Additional folding
        case 0x1D4B4: out[0] = 0x0079; *count = 1; break; // Additional folding
        case 0x1D4B5: out[0] = 0x007A; *count = 1; break; // Additional folding
        case 0x1D4D0: out[0] = 0x0061; *count = 1; break; // Additional folding
        case 0x1D4D1: out[0] = 0x0062; *count = 1; break; // Additional folding
        case 0x1D4D2: out[0] = 0x0063; *count = 1; break; // Additional folding
        case 0x1D4D3: out[0] = 0x0064; *count = 1; break; // Additional folding
        case 0x1D4D4: out[0] = 0x0065; *count = 1; break; // Additional folding
        case 0x1D4D5: out[0] = 0x0066; *count = 1; break; // Additional folding
        case 0x1D4D6: out[0] = 0x0067; *count = 1; break; // Additional folding
        case 0x1D4D7: out[0] = 0x0068; *count = 1; break; // Additional folding
        case 0x1D4D8: out[0] = 0x0069; *count = 1; break; // Additional folding
        case 0x1D4D9: out[0] = 0x006A; *count = 1; break; // Additional folding
        case 0x1D4DA: out[0] = 0x006B; *count = 1; break; // Additional folding
        case 0x1D4DB: out[0] = 0x006C; *count = 1; break; // Additional folding
        case 0x1D4DC: out[0] = 0x006D; *count = 1; break; // Additional folding
        case 0x1D4DD: out[0] = 0x006E; *count = 1; break; // Additional folding
        case 0x1D4DE: out[0] = 0x006F; *count = 1; break; // Additional folding
        case 0x1D4DF: out[0] = 0x0070; *count = 1; break; // Additional folding
        case 0x1D4E0: out[0] = 0x0071; *count = 1; break; // Additional folding
        case 0x1D4E1: out[0] = 0x0072; *count = 1; break; // Additional folding
        case 0x1D4E2: out[0] = 0x0073; *count = 1; break; // Additional folding
        case 0x1D4E3: out[0] = 0x0074; *count = 1; break; // Additional folding
        case 0x1D4E4: out[0] = 0x0075; *count = 1; break; // Additional folding
        case 0x1D4E5: out[0] = 0x0076; *count = 1; break; // Additional folding
        case 0x1D4E6: out[0] = 0x0077; *count = 1; break; // Additional folding
        case 0x1D4E7: out[0] = 0x0078; *count = 1; break; // Additional folding
        case 0x1D4E8: out[0] = 0x0079; *count = 1; break; // Additional folding
        case 0x1D4E9: out[0] = 0x007A; *count = 1; break; // Additional folding
        case 0x1D504: out[0] = 0x0061; *count = 1; break; // Additional folding
        case 0x1D505: out[0] = 0x0062; *count = 1; break; // Additional folding
        case 0x1D507: out[0] = 0x0064; *count = 1; break; // Additional folding
        case 0x1D508: out[0] = 0x0065; *count = 1; break; // Additional folding
        case 0x1D509: out[0] = 0x0066; *count = 1; break; // Additional folding
        case 0x1D50A: out[0] = 0x0067; *count = 1; break; // Additional folding
        case 0x1D50D: out[0] = 0x006A; *count = 1; break; // Additional folding
        case 0x1D50E: out[0] = 0x006B; *count = 1; break; // Additional folding
        case 0x1D50F: out[0] = 0x006C; *count = 1; break; // Additional folding
        case 0x1D510: out[0] = 0x006D; *count = 1; break; // Additional folding
        case 0x1D511: out[0] = 0x006E; *count = 1; break; // Additional folding
        case 0x1D512: out[0] = 0x006F; *count = 1; break; // Additional folding
        case 0x1D513: out[0] = 0x0070; *count = 1; break; // Additional folding
        case 0x1D514: out[0] = 0x0071; *count = 1; break; // Additional folding
        case 0x1D516: out[0] = 0x0073; *count = 1; break; // Additional folding
        case 0x1D517: out[0] = 0x0074; *count = 1; break; // Additional folding
        case 0x1D518: out[0] = 0x0075; *count = 1; break; // Additional folding
        case 0x1D519: out[0] = 0x0076; *count = 1; break; // Additional folding
        case 0x1D51A: out[0] = 0x0077; *count = 1; break; // Additional folding
        case 0x1D51B: out[0] = 0x0078; *count = 1; break; // Additional folding
        case 0x1D51C: out[0] = 0x0079; *count = 1; break; // Additional folding
        case 0x1D538: out[0] = 0x0061; *count = 1; break; // Additional folding
        case 0x1D539: out[0] = 0x0062; *count = 1; break; // Additional folding
        case 0x1D53B: out[0] = 0x0064; *count = 1; break; // Additional folding
        case 0x1D53C: out[0] = 0x0065; *count = 1; break; // Additional folding
        case 0x1D53D: out[0] = 0x0066; *count = 1; break; // Additional folding
        case 0x1D53E: out[0] = 0x0067; *count = 1; break; // Additional folding
        case 0x1D540: out[0] = 0x0069; *count = 1; break; // Additional folding
        case 0x1D541: out[0] = 0x006A; *count = 1; break; // Additional folding
        case 0x1D542: out[0] = 0x006B; *count = 1; break; // Additional folding
        case 0x1D543: out[0] = 0x006C; *count = 1; break; // Additional folding
        case 0x1D544: out[0] = 0x006D; *count = 1; break; // Additional folding
        case 0x1D546: out[0] = 0x006F; *count = 1; break; // Additional folding
        case 0x1D54A: out[0] = 0x0073; *count = 1; break; // Additional folding
        case 0x1D54B: out[0] = 0x0074; *count = 1; break; // Additional folding
        case 0x1D54C: out[0] = 0x0075; *count = 1; break; // Additional folding
        case 0x1D54D: out[0] = 0x0076; *count = 1; break; // Additional folding
        case 0x1D54E: out[0] = 0x0077; *count = 1; break; // Additional folding
        case 0x1D54F: out[0] = 0x0078; *count = 1; break; // Additional folding
        case 0x1D550: out[0] = 0x0079; *count = 1; break; // Additional folding
        case 0x1D56C: out[0] = 0x0061; *count = 1; break; // Additional folding
        case 0x1D56D: out[0] = 0x0062; *count = 1; break; // Additional folding
        case 0x1D56E: out[0] = 0x0063; *count = 1; break; // Additional folding
        case 0x1D56F: out[0] = 0x0064; *count = 1; break; // Additional folding
        case 0x1D570: out[0] = 0x0065; *count = 1; break; // Additional folding
        case 0x1D571: out[0] = 0x0066; *count = 1; break; // Additional folding
        case 0x1D572: out[0] = 0x0067; *count = 1; break; // Additional folding
        case 0x1D573: out[0] = 0x0068; *count = 1; break; // Additional folding
        case 0x1D574: out[0] = 0x0069; *count = 1; break; // Additional folding
        case 0x1D575: out[0] = 0x006A; *count = 1; break; // Additional folding
        case 0x1D576: out[0] = 0x006B; *count = 1; break; // Additional folding
        case 0x1D577: out[0] = 0x006C; *count = 1; break; // Additional folding
        case 0x1D578: out[0] = 0x006D; *count = 1; break; // Additional folding
        case 0x1D579: out[0] = 0x006E; *count = 1; break; // Additional folding
        case 0x1D57A: out[0] = 0x006F; *count = 1; break; // Additional folding
        case 0x1D57B: out[0] = 0x0070; *count = 1; break; // Additional folding
        case 0x1D57C: out[0] = 0x0071; *count = 1; break; // Additional folding
        case 0x1D57D: out[0] = 0x0072; *count = 1; break; // Additional folding
        case 0x1D57E: out[0] = 0x0073; *count = 1; break; // Additional folding
        case 0x1D57F: out[0] = 0x0074; *count = 1; break; // Additional folding
        case 0x1D580: out[0] = 0x0075; *count = 1; break; // Additional folding
        case 0x1D581: out[0] = 0x0076; *count = 1; break; // Additional folding
        case 0x1D582: out[0] = 0x0077; *count = 1; break; // Additional folding
        case 0x1D583: out[0] = 0x0078; *count = 1; break; // Additional folding
        case 0x1D584: out[0] = 0x0079; *count = 1; break; // Additional folding
        case 0x1D585: out[0] = 0x007A; *count = 1; break; // Additional folding
        case 0x1D5A0: out[0] = 0x0061; *count = 1; break; // Additional folding
        case 0x1D5A1: out[0] = 0x0062; *count = 1; break; // Additional folding
        case 0x1D5A2: out[0] = 0x0063; *count = 1; break; // Additional folding
        case 0x1D5A3: out[0] = 0x0064; *count = 1; break; // Additional folding
        case 0x1D5A4: out[0] = 0x0065; *count = 1; break; // Additional folding
        case 0x1D5A5: out[0] = 0x0066; *count = 1; break; // Additional folding
        case 0x1D5A6: out[0] = 0x0067; *count = 1; break; // Additional folding
        case 0x1D5A7: out[0] = 0x0068; *count = 1; break; // Additional folding
        case 0x1D5A8: out[0] = 0x0069; *count = 1; break; // Additional folding
        case 0x1D5A9: out[0] = 0x006A; *count = 1; break; // Additional folding
        case 0x1D5AA: out[0] = 0x006B; *count = 1; break; // Additional folding
        case 0x1D5AB: out[0] = 0x006C; *count = 1; break; // Additional folding
        case 0x1D5AC: out[0] = 0x006D; *count = 1; break; // Additional folding
        case 0x1D5AD: out[0] = 0x006E; *count = 1; break; // Additional folding
        case 0x1D5AE: out[0] = 0x006F; *count = 1; break; // Additional folding
        case 0x1D5AF: out[0] = 0x0070; *count = 1; break; // Additional folding
        case 0x1D5B0: out[0] = 0x0071; *count = 1; break; // Additional folding
        case 0x1D5B1: out[0] = 0x0072; *count = 1; break; // Additional folding
        case 0x1D5B2: out[0] = 0x0073; *count = 1; break; // Additional folding
        case 0x1D5B3: out[0] = 0x0074; *count = 1; break; // Additional folding
        case 0x1D5B4: out[0] = 0x0075; *count = 1; break; // Additional folding
        case 0x1D5B5: out[0] = 0x0076; *count = 1; break; // Additional folding
        case 0x1D5B6: out[0] = 0x0077; *count = 1; break; // Additional folding
        case 0x1D5B7: out[0] = 0x0078; *count = 1; break; // Additional folding
        case 0x1D5B8: out[0] = 0x0079; *count = 1; break; // Additional folding
        case 0x1D5B9: out[0] = 0x007A; *count = 1; break; // Additional folding
        case 0x1D5D4: out[0] = 0x0061; *count = 1; break; // Additional folding
        case 0x1D5D5: out[0] = 0x0062; *count = 1; break; // Additional folding
        case 0x1D5D6: out[0] = 0x0063; *count = 1; break; // Additional folding
        case 0x1D5D7: out[0] = 0x0064; *count = 1; break; // Additional folding
        case 0x1D5D8: out[0] = 0x0065; *count = 1; break; // Additional folding
        case 0x1D5D9: out[0] = 0x0066; *count = 1; break; // Additional folding
        case 0x1D5DA: out[0] = 0x0067; *count = 1; break; // Additional folding
        case 0x1D5DB: out[0] = 0x0068; *count = 1; break; // Additional folding
        case 0x1D5DC: out[0] = 0x0069; *count = 1; break; // Additional folding
        case 0x1D5DD: out[0] = 0x006A; *count = 1; break; // Additional folding
        case 0x1D5DE: out[0] = 0x006B; *count = 1; break; // Additional folding
        case 0x1D5DF: out[0] = 0x006C; *count = 1; break; // Additional folding
        case 0x1D5E0: out[0] = 0x006D; *count = 1; break; // Additional folding
        case 0x1D5E1: out[0] = 0x006E; *count = 1; break; // Additional folding
        case 0x1D5E2: out[0] = 0x006F; *count = 1; break; // Additional folding
        case 0x1D5E3: out[0] = 0x0070; *count = 1; break; // Additional folding
        case 0x1D5E4: out[0] = 0x0071; *count = 1; break; // Additional folding
        case 0x1D5E5: out[0] = 0x0072; *count = 1; break; // Additional folding
        case 0x1D5E6: out[0] = 0x0073; *count = 1; break; // Additional folding
        case 0x1D5E7: out[0] = 0x0074; *count = 1; break; // Additional folding
        case 0x1D5E8: out[0] = 0x0075; *count = 1; break; // Additional folding
        case 0x1D5E9: out[0] = 0x0076; *count = 1; break; // Additional folding
        case 0x1D5EA: out[0] = 0x0077; *count = 1; break; // Additional folding
        case 0x1D5EB: out[0] = 0x0078; *count = 1; break; // Additional folding
        case 0x1D5EC: out[0] = 0x0079; *count = 1; break; // Additional folding
        case 0x1D5ED: out[0] = 0x007A; *count = 1; break; // Additional folding
        case 0x1D608: out[0] = 0x0061; *count = 1; break; // Additional folding
        case 0x1D609: out[0] = 0x0062; *count = 1; break; // Additional folding
        case 0x1D60A: out[0] = 0x0063; *count = 1; break; // Additional folding
        case 0x1D60B: out[0] = 0x0064; *count = 1; break; // Additional folding
        case 0x1D60C: out[0] = 0x0065; *count = 1; break; // Additional folding
        case 0x1D60D: out[0] = 0x0066; *count = 1; break; // Additional folding
        case 0x1D60E: out[0] = 0x0067; *count = 1; break; // Additional folding
        case 0x1D60F: out[0] = 0x0068; *count = 1; break; // Additional folding
        case 0x1D610: out[0] = 0x0069; *count = 1; break; // Additional folding
        case 0x1D611: out[0] = 0x006A; *count = 1; break; // Additional folding
        case 0x1D612: out[0] = 0x006B; *count = 1; break; // Additional folding
        case 0x1D613: out[0] = 0x006C; *count = 1; break; // Additional folding
        case 0x1D614: out[0] = 0x006D; *count = 1; break; // Additional folding
        case 0x1D615: out[0] = 0x006E; *count = 1; break; // Additional folding
        case 0x1D616: out[0] = 0x006F; *count = 1; break; // Additional folding
        case 0x1D617: out[0] = 0x0070; *count = 1; break; // Additional folding
        case 0x1D618: out[0] = 0x0071; *count = 1; break; // Additional folding
        case 0x1D619: out[0] = 0x0072; *count = 1; break; // Additional folding
        case 0x1D61A: out[0] = 0x0073; *count = 1; break; // Additional folding
        case 0x1D61B: out[0] = 0x0074; *count = 1; break; // Additional folding
        case 0x1D61C: out[0] = 0x0075; *count = 1; break; // Additional folding
        case 0x1D61D: out[0] = 0x0076; *count = 1; break; // Additional folding
        case 0x1D61E: out[0] = 0x0077; *count = 1; break; // Additional folding
        case 0x1D61F: out[0] = 0x0078; *count = 1; break; // Additional folding
        case 0x1D620: out[0] = 0x0079; *count = 1; break; // Additional folding
        case 0x1D621: out[0] = 0x007A; *count = 1; break; // Additional folding
        case 0x1D63C: out[0] = 0x0061; *count = 1; break; // Additional folding
        case 0x1D63D: out[0] = 0x0062; *count = 1; break; // Additional folding
        case 0x1D63E: out[0] = 0x0063; *count = 1; break; // Additional folding
        case 0x1D63F: out[0] = 0x0064; *count = 1; break; // Additional folding
        case 0x1D640: out[0] = 0x0065; *count = 1; break; // Additional folding
        case 0x1D641: out[0] = 0x0066; *count = 1; break; // Additional folding
        case 0x1D642: out[0] = 0x0067; *count = 1; break; // Additional folding
        case 0x1D643: out[0] = 0x0068; *count = 1; break; // Additional folding
        case 0x1D644: out[0] = 0x0069; *count = 1; break; // Additional folding
        case 0x1D645: out[0] = 0x006A; *count = 1; break; // Additional folding
        case 0x1D646: out[0] = 0x006B; *count = 1; break; // Additional folding
        case 0x1D647: out[0] = 0x006C; *count = 1; break; // Additional folding
        case 0x1D648: out[0] = 0x006D; *count = 1; break; // Additional folding
        case 0x1D649: out[0] = 0x006E; *count = 1; break; // Additional folding
        case 0x1D64A: out[0] = 0x006F; *count = 1; break; // Additional folding
        case 0x1D64B: out[0] = 0x0070; *count = 1; break; // Additional folding
        case 0x1D64C: out[0] = 0x0071; *count = 1; break; // Additional folding
        case 0x1D64D: out[0] = 0x0072; *count = 1; break; // Additional folding
        case 0x1D64E: out[0] = 0x0073; *count = 1; break; // Additional folding
        case 0x1D64F: out[0] = 0x0074; *count = 1; break; // Additional folding
        case 0x1D650: out[0] = 0x0075; *count = 1; break; // Additional folding
        case 0x1D651: out[0] = 0x0076; *count = 1; break; // Additional folding
        case 0x1D652: out[0] = 0x0077; *count = 1; break; // Additional folding
        case 0x1D653: out[0] = 0x0078; *count = 1; break; // Additional folding
        case 0x1D654: out[0] = 0x0079; *count = 1; break; // Additional folding
        case 0x1D655: out[0] = 0x007A; *count = 1; break; // Additional folding
        case 0x1D670: out[0] = 0x0061; *count = 1; break; // Additional folding
        case 0x1D671: out[0] = 0x0062; *count = 1; break; // Additional folding
        case 0x1D672: out[0] = 0x0063; *count = 1; break; // Additional folding
        case 0x1D673: out[0] = 0x0064; *count = 1; break; // Additional folding
        case 0x1D674: out[0] = 0x0065; *count = 1; break; // Additional folding
        case 0x1D675: out[0] = 0x0066; *count = 1; break; // Additional folding
        case 0x1D676: out[0] = 0x0067; *count = 1; break; // Additional folding
        case 0x1D677: out[0] = 0x0068; *count = 1; break; // Additional folding
        case 0x1D678: out[0] = 0x0069; *count = 1; break; // Additional folding
        case 0x1D679: out[0] = 0x006A; *count = 1; break; // Additional folding
        case 0x1D67A: out[0] = 0x006B; *count = 1; break; // Additional folding
        case 0x1D67B: out[0] = 0x006C; *count = 1; break; // Additional folding
        case 0x1D67C: out[0] = 0x006D; *count = 1; break; // Additional folding
        case 0x1D67D: out[0] = 0x006E; *count = 1; break; // Additional folding
        case 0x1D67E: out[0] = 0x006F; *count = 1; break; // Additional folding
        case 0x1D67F: out[0] = 0x0070; *count = 1; break; // Additional folding
        case 0x1D680: out[0] = 0x0071; *count = 1; break; // Additional folding
        case 0x1D681: out[0] = 0x0072; *count = 1; break; // Additional folding
        case 0x1D682: out[0] = 0x0073; *count = 1; break; // Additional folding
        case 0x1D683: out[0] = 0x0074; *count = 1; break; // Additional folding
        case 0x1D684: out[0] = 0x0075; *count = 1; break; // Additional folding
        case 0x1D685: out[0] = 0x0076; *count = 1; break; // Additional folding
        case 0x1D686: out[0] = 0x0077; *count = 1; break; // Additional folding
        case 0x1D687: out[0] = 0x0078; *count = 1; break; // Additional folding
        case 0x1D688: out[0] = 0x0079; *count = 1; break; // Additional folding
        case 0x1D689: out[0] = 0x007A; *count = 1; break; // Additional folding
        case 0x1D6A8: out[0] = 0x03B1; *count = 1; break; // Additional folding
        case 0x1D6A9: out[0] = 0x03B2; *count = 1; break; // Additional folding
        case 0x1D6AA: out[0] = 0x03B3; *count = 1; break; // Additional folding
        case 0x1D6AB: out[0] = 0x03B4; *count = 1; break; // Additional folding
        case 0x1D6AC: out[0] = 0x03B5; *count = 1; break; // Additional folding
        case 0x1D6AD: out[0] = 0x03B6; *count = 1; break; // Additional folding
        case 0x1D6AE: out[0] = 0x03B7; *count = 1; break; // Additional folding
        case 0x1D6AF: out[0] = 0x03B8; *count = 1; break; // Additional folding
        case 0x1D6B0: out[0] = 0x03B9; *count = 1; break; // Additional folding
        case 0x1D6B1: out[0] = 0x03BA; *count = 1; break; // Additional folding
        case 0x1D6B2: out[0] = 0x03BB; *count = 1; break; // Additional folding
        case 0x1D6B3: out[0] = 0x03BC; *count = 1; break; // Additional folding
        case 0x1D6B4: out[0] = 0x03BD; *count = 1; break; // Additional folding
        case 0x1D6B5: out[0] = 0x03BE; *count = 1; break; // Additional folding
        case 0x1D6B6: out[0] = 0x03BF; *count = 1; break; // Additional folding
        case 0x1D6B7: out[0] = 0x03C0; *count = 1; break; // Additional folding
        case 0x1D6B8: out[0] = 0x03C1; *count = 1; break; // Additional folding
        case 0x1D6B9: out[0] = 0x03B8; *count = 1; break; // Additional folding
        case 0x1D6BA: out[0] = 0x03C3; *count = 1; break; // Additional folding
        case 0x1D6BB: out[0] = 0x03C4; *count = 1; break; // Additional folding
        case 0x1D6BC: out[0] = 0x03C5; *count = 1; break; // Additional folding
        case 0x1D6BD: out[0] = 0x03C6; *count = 1; break; // Additional folding
        case 0x1D6BE: out[0] = 0x03C7; *count = 1; break; // Additional folding
        case 0x1D6BF: out[0] = 0x03C8; *count = 1; break; // Additional folding
        case 0x1D6C0: out[0] = 0x03C9; *count = 1; break; // Additional folding
        case 0x1D6D3: out[0] = 0x03C3; *count = 1; break; // Additional folding
        case 0x1D6E2: out[0] = 0x03B1; *count = 1; break; // Additional folding
        case 0x1D6E3: out[0] = 0x03B2; *count = 1; break; // Additional folding
        case 0x1D6E4: out[0] = 0x03B3; *count = 1; break; // Additional folding
        case 0x1D6E5: out[0] = 0x03B4; *count = 1; break; // Additional folding
        case 0x1D6E6: out[0] = 0x03B5; *count = 1; break; // Additional folding
        case 0x1D6E7: out[0] = 0x03B6; *count = 1; break; // Additional folding
        case 0x1D6E8: out[0] = 0x03B7; *count = 1; break; // Additional folding
        case 0x1D6E9: out[0] = 0x03B8; *count = 1; break; // Additional folding
        case 0x1D6EA: out[0] = 0x03B9; *count = 1; break; // Additional folding
        case 0x1D6EB: out[0] = 0x03BA; *count = 1; break; // Additional folding
        case 0x1D6EC: out[0] = 0x03BB; *count = 1; break; // Additional folding
        case 0x1D6ED: out[0] = 0x03BC; *count = 1; break; // Additional folding
        case 0x1D6EE: out[0] = 0x03BD; *count = 1; break; // Additional folding
        case 0x1D6EF: out[0] = 0x03BE; *count = 1; break; // Additional folding
        case 0x1D6F0: out[0] = 0x03BF; *count = 1; break; // Additional folding
        case 0x1D6F1: out[0] = 0x03C0; *count = 1; break; // Additional folding
        case 0x1D6F2: out[0] = 0x03C1; *count = 1; break; // Additional folding
        case 0x1D6F3: out[0] = 0x03B8; *count = 1; break; // Additional folding
        case 0x1D6F4: out[0] = 0x03C3; *count = 1; break; // Additional folding
        case 0x1D6F5: out[0] = 0x03C4; *count = 1; break; // Additional folding
        case 0x1D6F6: out[0] = 0x03C5; *count = 1; break; // Additional folding
        case 0x1D6F7: out[0] = 0x03C6; *count = 1; break; // Additional folding
        case 0x1D6F8: out[0] = 0x03C7; *count = 1; break; // Additional folding
        case 0x1D6F9: out[0] = 0x03C8; *count = 1; break; // Additional folding
        case 0x1D6FA: out[0] = 0x03C9; *count = 1; break; // Additional folding
        case 0x1D70D: out[0] = 0x03C3; *count = 1; break; // Additional folding
        case 0x1D71C: out[0] = 0x03B1; *count = 1; break; // Additional folding
        case 0x1D71D: out[0] = 0x03B2; *count = 1; break; // Additional folding
        case 0x1D71E: out[0] = 0x03B3; *count = 1; break; // Additional folding
        case 0x1D71F: out[0] = 0x03B4; *count = 1; break; // Additional folding
        case 0x1D720: out[0] = 0x03B5; *count = 1; break; // Additional folding
        case 0x1D721: out[0] = 0x03B6; *count = 1; break; // Additional folding
        case 0x1D722: out[0] = 0x03B7; *count = 1; break; // Additional folding
        case 0x1D723: out[0] = 0x03B8; *count = 1; break; // Additional folding
        case 0x1D724: out[0] = 0x03B9; *count = 1; break; // Additional folding
        case 0x1D725: out[0] = 0x03BA; *count = 1; break; // Additional folding
        case 0x1D726: out[0] = 0x03BB; *count = 1; break; // Additional folding
        case 0x1D727: out[0] = 0x03BC; *count = 1; break; // Additional folding
        case 0x1D728: out[0] = 0x03BD; *count = 1; break; // Additional folding
        case 0x1D729: out[0] = 0x03BE; *count = 1; break; // Additional folding
        case 0x1D72A: out[0] = 0x03BF; *count = 1; break; // Additional folding
        case 0x1D72B: out[0] = 0x03C0; *count = 1; break; // Additional folding
        case 0x1D72C: out[0] = 0x03C1; *count = 1; break; // Additional folding
        case 0x1D72D: out[0] = 0x03B8; *count = 1; break; // Additional folding
        case 0x1D72E: out[0] = 0x03C3; *count = 1; break; // Additional folding
        case 0x1D72F: out[0] = 0x03C4; *count = 1; break; // Additional folding
        case 0x1D730: out[0] = 0x03C5; *count = 1; break; // Additional folding
        case 0x1D731: out[0] = 0x03C6; *count = 1; break; // Additional folding
        case 0x1D732: out[0] = 0x03C7; *count = 1; break; // Additional folding
        case 0x1D733: out[0] = 0x03C8; *count = 1; break; // Additional folding
        case 0x1D734: out[0] = 0x03C9; *count = 1; break; // Additional folding
        case 0x1D747: out[0] = 0x03C3; *count = 1; break; // Additional folding
        case 0x1D756: out[0] = 0x03B1; *count = 1; break; // Additional folding
        case 0x1D757: out[0] = 0x03B2; *count = 1; break; // Additional folding
        case 0x1D758: out[0] = 0x03B3; *count = 1; break; // Additional folding
        case 0x1D759: out[0] = 0x03B4; *count = 1; break; // Additional folding
        case 0x1D75A: out[0] = 0x03B5; *count = 1; break; // Additional folding
        case 0x1D75B: out[0] = 0x03B6; *count = 1; break; // Additional folding
        case 0x1D75C: out[0] = 0x03B7; *count = 1; break; // Additional folding
        case 0x1D75D: out[0] = 0x03B8; *count = 1; break; // Additional folding
        case 0x1D75E: out[0] = 0x03B9; *count = 1; break; // Additional folding
        case 0x1D75F: out[0] = 0x03BA; *count = 1; break; // Additional folding
        case 0x1D760: out[0] = 0x03BB; *count = 1; break; // Additional folding
        case 0x1D761: out[0] = 0x03BC; *count = 1; break; // Additional folding
        case 0x1D762: out[0] = 0x03BD; *count = 1; break; // Additional folding
        case 0x1D763: out[0] = 0x03BE; *count = 1; break; // Additional folding
        case 0x1D764: out[0] = 0x03BF; *count = 1; break; // Additional folding
        case 0x1D765: out[0] = 0x03C0; *count = 1; break; // Additional folding
        case 0x1D766: out[0] = 0x03C1; *count = 1; break; // Additional folding
        case 0x1D767: out[0] = 0x03B8; *count = 1; break; // Additional folding
        case 0x1D768: out[0] = 0x03C3; *count = 1; break; // Additional folding
        case 0x1D769: out[0] = 0x03C4; *count = 1; break; // Additional folding
        case 0x1D76A: out[0] = 0x03C5; *count = 1; break; // Additional folding
        case 0x1D76B: out[0] = 0x03C6; *count = 1; break; // Additional folding
        case 0x1D76C: out[0] = 0x03C7; *count = 1; break; // Additional folding
        case 0x1D76D: out[0] = 0x03C8; *count = 1; break; // Additional folding
        case 0x1D76E: out[0] = 0x03C9; *count = 1; break; // Additional folding
        case 0x1D781: out[0] = 0x03C3; *count = 1; break; // Additional folding
        case 0x1D790: out[0] = 0x03B1; *count = 1; break; // Additional folding
        case 0x1D791: out[0] = 0x03B2; *count = 1; break; // Additional folding
        case 0x1D792: out[0] = 0x03B3; *count = 1; break; // Additional folding
        case 0x1D793: out[0] = 0x03B4; *count = 1; break; // Additional folding
        case 0x1D794: out[0] = 0x03B5; *count = 1; break; // Additional folding
        case 0x1D795: out[0] = 0x03B6; *count = 1; break; // Additional folding
        case 0x1D796: out[0] = 0x03B7; *count = 1; break; // Additional folding
        case 0x1D797: out[0] = 0x03B8; *count = 1; break; // Additional folding
        case 0x1D798: out[0] = 0x03B9; *count = 1; break; // Additional folding
        case 0x1D799: out[0] = 0x03BA; *count = 1; break; // Additional folding
        case 0x1D79A: out[0] = 0x03BB; *count = 1; break; // Additional folding
        case 0x1D79B: out[0] = 0x03BC; *count = 1; break; // Additional folding
        case 0x1D79C: out[0] = 0x03BD; *count = 1; break; // Additional folding
        case 0x1D79D: out[0] = 0x03BE; *count = 1; break; // Additional folding
        case 0x1D79E: out[0] = 0x03BF; *count = 1; break; // Additional folding
        case 0x1D79F: out[0] = 0x03C0; *count = 1; break; // Additional folding
        case 0x1D7A0: out[0] = 0x03C1; *count = 1; break; // Additional folding
        case 0x1D7A1: out[0] = 0x03B8; *count = 1; break; // Additional folding
        case 0x1D7A2: out[0] = 0x03C3; *count = 1; break; // Additional folding
        case 0x1D7A3: out[0] = 0x03C4; *count = 1; break; // Additional folding
        case 0x1D7A4: out[0] = 0x03C5; *count = 1; break; // Additional folding
        case 0x1D7A5: out[0] = 0x03C6; *count = 1; break; // Additional folding
        case 0x1D7A6: out[0] = 0x03C7; *count = 1; break; // Additional folding
        case 0x1D7A7: out[0] = 0x03C8; *count = 1; break; // Additional folding
        case 0x1D7A8: out[0] = 0x03C9; *count = 1; break; // Additional folding
        case 0x1D7BB: out[0] = 0x03C3; *count = 1; break; // Additional folding
        default: out[0] = val; *count = 1; break;
        }
    }

    bool LDAPMatcher::isUnassignedCodePoint(uint32_t val) {
        if (val == 0x0221) return true;
        if (val >= 0x0234 && val <= 0x024F) return true;
        if (val >= 0x02AE && val <= 0x02AF) return true;
        if (val >= 0x02EF && val <= 0x02FF) return true;
        if (val >= 0x0350 && val <= 0x035F) return true;
        if (val >= 0x0370 && val <= 0x0373) return true;
        if (val >= 0x0376 && val <= 0x0379) return true;
        if (val >= 0x037B && val <= 0x037D) return true;
        if (val >= 0x037F && val <= 0x0383) return true;
        if (val == 0x038B) return true;
        if (val == 0x038D) return true;
        if (val == 0x03A2) return true;
        if (val == 0x03CF) return true;
        if (val >= 0x03F7 && val <= 0x03FF) return true;
        if (val == 0x0487) return true;
        if (val == 0x04CF) return true;
        if (val >= 0x04F6 && val <= 0x04F7) return true;
        if (val >= 0x04FA && val <= 0x04FF) return true;
        if (val >= 0x0510 && val <= 0x0530) return true;
        if (val >= 0x0557 && val <= 0x0558) return true;
        if (val == 0x0560) return true;
        if (val == 0x0588) return true;
        if (val >= 0x058B && val <= 0x0590) return true;
        if (val == 0x05A2) return true;
        if (val == 0x05BA) return true;
        if (val >= 0x05C5 && val <= 0x05CF) return true;
        if (val >= 0x05EB && val <= 0x05EF) return true;
        if (val >= 0x05F5 && val <= 0x060B) return true;
        if (val >= 0x060D && val <= 0x061A) return true;
        if (val >= 0x061C && val <= 0x061E) return true;
        if (val == 0x0620) return true;
        if (val >= 0x063B && val <= 0x063F) return true;
        if (val >= 0x0656 && val <= 0x065F) return true;
        if (val >= 0x06EE && val <= 0x06EF) return true;
        if (val == 0x06FF) return true;
        if (val == 0x070E) return true;
        if (val >= 0x072D && val <= 0x072F) return true;
        if (val >= 0x074B && val <= 0x077F) return true;
        if (val >= 0x07B2 && val <= 0x0900) return true;
        if (val == 0x0904) return true;
        if (val >= 0x093A && val <= 0x093B) return true;
        if (val >= 0x094E && val <= 0x094F) return true;
        if (val >= 0x0955 && val <= 0x0957) return true;
        if (val >= 0x0971 && val <= 0x0980) return true;
        if (val == 0x0984) return true;
        if (val >= 0x098D && val <= 0x098E) return true;
        if (val >= 0x0991 && val <= 0x0992) return true;
        if (val == 0x09A9) return true;
        if (val == 0x09B1) return true;
        if (val >= 0x09B3 && val <= 0x09B5) return true;
        if (val >= 0x09BA && val <= 0x09BB) return true;
        if (val == 0x09BD) return true;
        if (val >= 0x09C5 && val <= 0x09C6) return true;
        if (val >= 0x09C9 && val <= 0x09CA) return true;
        if (val >= 0x09CE && val <= 0x09D6) return true;
        if (val >= 0x09D8 && val <= 0x09DB) return true;
        if (val == 0x09DE) return true;
        if (val >= 0x09E4 && val <= 0x09E5) return true;
        if (val >= 0x09FB && val <= 0x0A01) return true;
        if (val >= 0x0A03 && val <= 0x0A04) return true;
        if (val >= 0x0A0B && val <= 0x0A0E) return true;
        if (val >= 0x0A11 && val <= 0x0A12) return true;
        if (val == 0x0A29) return true;
        if (val == 0x0A31) return true;
        if (val == 0x0A34) return true;
        if (val == 0x0A37) return true;
        if (val >= 0x0A3A && val <= 0x0A3B) return true;
        if (val == 0x0A3D) return true;
        if (val >= 0x0A43 && val <= 0x0A46) return true;
        if (val >= 0x0A49 && val <= 0x0A4A) return true;
        if (val >= 0x0A4E && val <= 0x0A58) return true;
        if (val == 0x0A5D) return true;
        if (val >= 0x0A5F && val <= 0x0A65) return true;
        if (val >= 0x0A75 && val <= 0x0A80) return true;
        if (val == 0x0A84) return true;
        if (val == 0x0A8C) return true;
        if (val == 0x0A8E) return true;
        if (val == 0x0A92) return true;
        if (val == 0x0AA9) return true;
        if (val == 0x0AB1) return true;
        if (val == 0x0AB4) return true;
        if (val >= 0x0ABA && val <= 0x0ABB) return true;
        if (val == 0x0AC6) return true;
        if (val == 0x0ACA) return true;
        if (val >= 0x0ACE && val <= 0x0ACF) return true;
        if (val >= 0x0AD1 && val <= 0x0ADF) return true;
        if (val >= 0x0AE1 && val <= 0x0AE5) return true;
        if (val >= 0x0AF0 && val <= 0x0B00) return true;
        if (val == 0x0B04) return true;
        if (val >= 0x0B0D && val <= 0x0B0E) return true;
        if (val >= 0x0B11 && val <= 0x0B12) return true;
        if (val == 0x0B29) return true;
        if (val == 0x0B31) return true;
        if (val >= 0x0B34 && val <= 0x0B35) return true;
        if (val >= 0x0B3A && val <= 0x0B3B) return true;
        if (val >= 0x0B44 && val <= 0x0B46) return true;
        if (val >= 0x0B49 && val <= 0x0B4A) return true;
        if (val >= 0x0B4E && val <= 0x0B55) return true;
        if (val >= 0x0B58 && val <= 0x0B5B) return true;
        if (val == 0x0B5E) return true;
        if (val >= 0x0B62 && val <= 0x0B65) return true;
        if (val >= 0x0B71 && val <= 0x0B81) return true;
        if (val == 0x0B84) return true;
        if (val >= 0x0B8B && val <= 0x0B8D) return true;
        if (val == 0x0B91) return true;
        if (val >= 0x0B96 && val <= 0x0B98) return true;
        if (val == 0x0B9B) return true;
        if (val == 0x0B9D) return true;
        if (val >= 0x0BA0 && val <= 0x0BA2) return true;
        if (val >= 0x0BA5 && val <= 0x0BA7) return true;
        if (val >= 0x0BAB && val <= 0x0BAD) return true;
        if (val == 0x0BB6) return true;
        if (val >= 0x0BBA && val <= 0x0BBD) return true;
        if (val >= 0x0BC3 && val <= 0x0BC5) return true;
        if (val == 0x0BC9) return true;
        if (val >= 0x0BCE && val <= 0x0BD6) return true;
        if (val >= 0x0BD8 && val <= 0x0BE6) return true;
        if (val >= 0x0BF3 && val <= 0x0C00) return true;
        if (val == 0x0C04) return true;
        if (val == 0x0C0D) return true;
        if (val == 0x0C11) return true;
        if (val == 0x0C29) return true;
        if (val == 0x0C34) return true;
        if (val >= 0x0C3A && val <= 0x0C3D) return true;
        if (val == 0x0C45) return true;
        if (val == 0x0C49) return true;
        if (val >= 0x0C4E && val <= 0x0C54) return true;
        if (val >= 0x0C57 && val <= 0x0C5F) return true;
        if (val >= 0x0C62 && val <= 0x0C65) return true;
        if (val >= 0x0C70 && val <= 0x0C81) return true;
        if (val == 0x0C84) return true;
        if (val == 0x0C8D) return true;
        if (val == 0x0C91) return true;
        if (val == 0x0CA9) return true;
        if (val == 0x0CB4) return true;
        if (val >= 0x0CBA && val <= 0x0CBD) return true;
        if (val == 0x0CC5) return true;
        if (val == 0x0CC9) return true;
        if (val >= 0x0CCE && val <= 0x0CD4) return true;
        if (val >= 0x0CD7 && val <= 0x0CDD) return true;
        if (val == 0x0CDF) return true;
        if (val >= 0x0CE2 && val <= 0x0CE5) return true;
        if (val >= 0x0CF0 && val <= 0x0D01) return true;
        if (val == 0x0D04) return true;
        if (val == 0x0D0D) return true;
        if (val == 0x0D11) return true;
        if (val == 0x0D29) return true;
        if (val >= 0x0D3A && val <= 0x0D3D) return true;
        if (val >= 0x0D44 && val <= 0x0D45) return true;
        if (val == 0x0D49) return true;
        if (val >= 0x0D4E && val <= 0x0D56) return true;
        if (val >= 0x0D58 && val <= 0x0D5F) return true;
        if (val >= 0x0D62 && val <= 0x0D65) return true;
        if (val >= 0x0D70 && val <= 0x0D81) return true;
        if (val == 0x0D84) return true;
        if (val >= 0x0D97 && val <= 0x0D99) return true;
        if (val == 0x0DB2) return true;
        if (val == 0x0DBC) return true;
        if (val >= 0x0DBE && val <= 0x0DBF) return true;
        if (val >= 0x0DC7 && val <= 0x0DC9) return true;
        if (val >= 0x0DCB && val <= 0x0DCE) return true;
        if (val == 0x0DD5) return true;
        if (val == 0x0DD7) return true;
        if (val >= 0x0DE0 && val <= 0x0DF1) return true;
        if (val >= 0x0DF5 && val <= 0x0E00) return true;
        if (val >= 0x0E3B && val <= 0x0E3E) return true;
        if (val >= 0x0E5C && val <= 0x0E80) return true;
        if (val == 0x0E83) return true;
        if (val >= 0x0E85 && val <= 0x0E86) return true;
        if (val == 0x0E89) return true;
        if (val >= 0x0E8B && val <= 0x0E8C) return true;
        if (val >= 0x0E8E && val <= 0x0E93) return true;
        if (val == 0x0E98) return true;
        if (val == 0x0EA0) return true;
        if (val == 0x0EA4) return true;
        if (val == 0x0EA6) return true;
        if (val >= 0x0EA8 && val <= 0x0EA9) return true;
        if (val == 0x0EAC) return true;
        if (val == 0x0EBA) return true;
        if (val >= 0x0EBE && val <= 0x0EBF) return true;
        if (val == 0x0EC5) return true;
        if (val == 0x0EC7) return true;
        if (val >= 0x0ECE && val <= 0x0ECF) return true;
        if (val >= 0x0EDA && val <= 0x0EDB) return true;
        if (val >= 0x0EDE && val <= 0x0EFF) return true;
        if (val == 0x0F48) return true;
        if (val >= 0x0F6B && val <= 0x0F70) return true;
        if (val >= 0x0F8C && val <= 0x0F8F) return true;
        if (val == 0x0F98) return true;
        if (val == 0x0FBD) return true;
        if (val >= 0x0FCD && val <= 0x0FCE) return true;
        if (val >= 0x0FD0 && val <= 0x0FFF) return true;
        if (val == 0x1022) return true;
        if (val == 0x1028) return true;
        if (val == 0x102B) return true;
        if (val >= 0x1033 && val <= 0x1035) return true;
        if (val >= 0x103A && val <= 0x103F) return true;
        if (val >= 0x105A && val <= 0x109F) return true;
        if (val >= 0x10C6 && val <= 0x10CF) return true;
        if (val >= 0x10F9 && val <= 0x10FA) return true;
        if (val >= 0x10FC && val <= 0x10FF) return true;
        if (val >= 0x115A && val <= 0x115E) return true;
        if (val >= 0x11A3 && val <= 0x11A7) return true;
        if (val >= 0x11FA && val <= 0x11FF) return true;
        if (val == 0x1207) return true;
        if (val == 0x1247) return true;
        if (val == 0x1249) return true;
        if (val >= 0x124E && val <= 0x124F) return true;
        if (val == 0x1257) return true;
        if (val == 0x1259) return true;
        if (val >= 0x125E && val <= 0x125F) return true;
        if (val == 0x1287) return true;
        if (val == 0x1289) return true;
        if (val >= 0x128E && val <= 0x128F) return true;
        if (val == 0x12AF) return true;
        if (val == 0x12B1) return true;
        if (val >= 0x12B6 && val <= 0x12B7) return true;
        if (val == 0x12BF) return true;
        if (val == 0x12C1) return true;
        if (val >= 0x12C6 && val <= 0x12C7) return true;
        if (val == 0x12CF) return true;
        if (val == 0x12D7) return true;
        if (val == 0x12EF) return true;
        if (val == 0x130F) return true;
        if (val == 0x1311) return true;
        if (val >= 0x1316 && val <= 0x1317) return true;
        if (val == 0x131F) return true;
        if (val == 0x1347) return true;
        if (val >= 0x135B && val <= 0x1360) return true;
        if (val >= 0x137D && val <= 0x139F) return true;
        if (val >= 0x13F5 && val <= 0x1400) return true;
        if (val >= 0x1677 && val <= 0x167F) return true;
        if (val >= 0x169D && val <= 0x169F) return true;
        if (val >= 0x16F1 && val <= 0x16FF) return true;
        if (val == 0x170D) return true;
        if (val >= 0x1715 && val <= 0x171F) return true;
        if (val >= 0x1737 && val <= 0x173F) return true;
        if (val >= 0x1754 && val <= 0x175F) return true;
        if (val == 0x176D) return true;
        if (val == 0x1771) return true;
        if (val >= 0x1774 && val <= 0x177F) return true;
        if (val >= 0x17DD && val <= 0x17DF) return true;
        if (val >= 0x17EA && val <= 0x17FF) return true;
        if (val == 0x180F) return true;
        if (val >= 0x181A && val <= 0x181F) return true;
        if (val >= 0x1878 && val <= 0x187F) return true;
        if (val >= 0x18AA && val <= 0x1DFF) return true;
        if (val >= 0x1E9C && val <= 0x1E9F) return true;
        if (val >= 0x1EFA && val <= 0x1EFF) return true;
        if (val >= 0x1F16 && val <= 0x1F17) return true;
        if (val >= 0x1F1E && val <= 0x1F1F) return true;
        if (val >= 0x1F46 && val <= 0x1F47) return true;
        if (val >= 0x1F4E && val <= 0x1F4F) return true;
        if (val == 0x1F58) return true;
        if (val == 0x1F5A) return true;
        if (val == 0x1F5C) return true;
        if (val == 0x1F5E) return true;
        if (val >= 0x1F7E && val <= 0x1F7F) return true;
        if (val == 0x1FB5) return true;
        if (val == 0x1FC5) return true;
        if (val >= 0x1FD4 && val <= 0x1FD5) return true;
        if (val == 0x1FDC) return true;
        if (val >= 0x1FF0 && val <= 0x1FF1) return true;
        if (val == 0x1FF5) return true;
        if (val == 0x1FFF) return true;
        if (val >= 0x2053 && val <= 0x2056) return true;
        if (val >= 0x2058 && val <= 0x205E) return true;
        if (val >= 0x2064 && val <= 0x2069) return true;
        if (val >= 0x2072 && val <= 0x2073) return true;
        if (val >= 0x208F && val <= 0x209F) return true;
        if (val >= 0x20B2 && val <= 0x20CF) return true;
        if (val >= 0x20EB && val <= 0x20FF) return true;
        if (val >= 0x213B && val <= 0x213C) return true;
        if (val >= 0x214C && val <= 0x2152) return true;
        if (val >= 0x2184 && val <= 0x218F) return true;
        if (val >= 0x23CF && val <= 0x23FF) return true;
        if (val >= 0x2427 && val <= 0x243F) return true;
        if (val >= 0x244B && val <= 0x245F) return true;
        if (val == 0x24FF) return true;
        if (val >= 0x2614 && val <= 0x2615) return true;
        if (val == 0x2618) return true;
        if (val >= 0x267E && val <= 0x267F) return true;
        if (val >= 0x268A && val <= 0x2700) return true;
        if (val == 0x2705) return true;
        if (val >= 0x270A && val <= 0x270B) return true;
        if (val == 0x2728) return true;
        if (val == 0x274C) return true;
        if (val == 0x274E) return true;
        if (val >= 0x2753 && val <= 0x2755) return true;
        if (val == 0x2757) return true;
        if (val >= 0x275F && val <= 0x2760) return true;
        if (val >= 0x2795 && val <= 0x2797) return true;
        if (val == 0x27B0) return true;
        if (val >= 0x27BF && val <= 0x27CF) return true;
        if (val >= 0x27EC && val <= 0x27EF) return true;
        if (val >= 0x2B00 && val <= 0x2E7F) return true;
        if (val == 0x2E9A) return true;
        if (val >= 0x2EF4 && val <= 0x2EFF) return true;
        if (val >= 0x2FD6 && val <= 0x2FEF) return true;
        if (val >= 0x2FFC && val <= 0x2FFF) return true;
        if (val == 0x3040) return true;
        if (val >= 0x3097 && val <= 0x3098) return true;
        if (val >= 0x3100 && val <= 0x3104) return true;
        if (val >= 0x312D && val <= 0x3130) return true;
        if (val == 0x318F) return true;
        if (val >= 0x31B8 && val <= 0x31EF) return true;
        if (val >= 0x321D && val <= 0x321F) return true;
        if (val >= 0x3244 && val <= 0x3250) return true;
        if (val >= 0x327C && val <= 0x327E) return true;
        if (val >= 0x32CC && val <= 0x32CF) return true;
        if (val == 0x32FF) return true;
        if (val >= 0x3377 && val <= 0x337A) return true;
        if (val >= 0x33DE && val <= 0x33DF) return true;
        if (val == 0x33FF) return true;
        if (val >= 0x4DB6 && val <= 0x4DFF) return true;
        if (val >= 0x9FA6 && val <= 0x9FFF) return true;
        if (val >= 0xA48D && val <= 0xA48F) return true;
        if (val >= 0xA4C7 && val <= 0xABFF) return true;
        if (val >= 0xD7A4 && val <= 0xD7FF) return true;
        if (val >= 0xFA2E && val <= 0xFA2F) return true;
        if (val >= 0xFA6B && val <= 0xFAFF) return true;
        if (val >= 0xFB07 && val <= 0xFB12) return true;
        if (val >= 0xFB18 && val <= 0xFB1C) return true;
        if (val == 0xFB37) return true;
        if (val == 0xFB3D) return true;
        if (val == 0xFB3F) return true;
        if (val == 0xFB42) return true;
        if (val == 0xFB45) return true;
        if (val >= 0xFBB2 && val <= 0xFBD2) return true;
        if (val >= 0xFD40 && val <= 0xFD4F) return true;
        if (val >= 0xFD90 && val <= 0xFD91) return true;
        if (val >= 0xFDC8 && val <= 0xFDCF) return true;
        if (val >= 0xFDFD && val <= 0xFDFF) return true;
        if (val >= 0xFE10 && val <= 0xFE1F) return true;
        if (val >= 0xFE24 && val <= 0xFE2F) return true;
        if (val >= 0xFE47 && val <= 0xFE48) return true;
        if (val == 0xFE53) return true;
        if (val == 0xFE67) return true;
        if (val >= 0xFE6C && val <= 0xFE6F) return true;
        if (val == 0xFE75) return true;
        if (val >= 0xFEFD && val <= 0xFEFE) return true;
        if (val == 0xFF00) return true;
        if (val >= 0xFFBF && val <= 0xFFC1) return true;
        if (val >= 0xFFC8 && val <= 0xFFC9) return true;
        if (val >= 0xFFD0 && val <= 0xFFD1) return true;
        if (val >= 0xFFD8 && val <= 0xFFD9) return true;
        if (val >= 0xFFDD && val <= 0xFFDF) return true;
        if (val == 0xFFE7) return true;
        if (val >= 0xFFEF && val <= 0xFFF8) return true;
        if (val >= 0x10000 && val <= 0x102FF) return true;
        if (val == 0x1031F) return true;
        if (val >= 0x10324 && val <= 0x1032F) return true;
        if (val >= 0x1034B && val <= 0x103FF) return true;
        if (val >= 0x10426 && val <= 0x10427) return true;
        if (val >= 0x1044E && val <= 0x1CFFF) return true;
        if (val >= 0x1D0F6 && val <= 0x1D0FF) return true;
        if (val >= 0x1D127 && val <= 0x1D129) return true;
        if (val >= 0x1D1DE && val <= 0x1D3FF) return true;
        if (val == 0x1D455) return true;
        if (val == 0x1D49D) return true;
        if (val >= 0x1D4A0 && val <= 0x1D4A1) return true;
        if (val >= 0x1D4A3 && val <= 0x1D4A4) return true;
        if (val >= 0x1D4A7 && val <= 0x1D4A8) return true;
        if (val == 0x1D4AD) return true;
        if (val == 0x1D4BA) return true;
        if (val == 0x1D4BC) return true;
        if (val == 0x1D4C1) return true;
        if (val == 0x1D4C4) return true;
        if (val == 0x1D506) return true;
        if (val >= 0x1D50B && val <= 0x1D50C) return true;
        if (val == 0x1D515) return true;
        if (val == 0x1D51D) return true;
        if (val == 0x1D53A) return true;
        if (val == 0x1D53F) return true;
        if (val == 0x1D545) return true;
        if (val >= 0x1D547 && val <= 0x1D549) return true;
        if (val == 0x1D551) return true;
        if (val >= 0x1D6A4 && val <= 0x1D6A7) return true;
        if (val >= 0x1D7CA && val <= 0x1D7CD) return true;
        if (val >= 0x1D800 && val <= 0x1FFFD) return true;
        if (val >= 0x2A6D7 && val <= 0x2F7FF) return true;
        if (val >= 0x2FA1E && val <= 0x2FFFD) return true;
        if (val >= 0x30000 && val <= 0x3FFFD) return true;
        if (val >= 0x40000 && val <= 0x4FFFD) return true;
        if (val >= 0x50000 && val <= 0x5FFFD) return true;
        if (val >= 0x60000 && val <= 0x6FFFD) return true;
        if (val >= 0x70000 && val <= 0x7FFFD) return true;
        if (val >= 0x80000 && val <= 0x8FFFD) return true;
        if (val >= 0x90000 && val <= 0x9FFFD) return true;
        if (val >= 0xA0000 && val <= 0xAFFFD) return true;
        if (val >= 0xB0000 && val <= 0xBFFFD) return true;
        if (val >= 0xC0000 && val <= 0xCFFFD) return true;
        if (val >= 0xD0000 && val <= 0xDFFFD) return true;
        if (val == 0xE0000) return true;
        if (val >= 0xE0002 && val <= 0xE001F) return true;
        if (val >= 0xE0080 && val <= 0xEFFFD) return true;

        return false;
    }

    bool LDAPMatcher::isProhibited(uint32_t val) {
        // C.8
        if (val == 0x0340) return true; // COMBINING GRAVE TONE MARK
        if (val == 0x0341) return true; // COMBINING ACUTE TONE MARK
        if (val == 0x200E) return true; // LEFT-TO-RIGHT MARK
        if (val == 0x200F) return true; // RIGHT-TO-LEFT MARK
        if (val == 0x202A) return true; // LEFT-TO-RIGHT EMBEDDING
        if (val == 0x202B) return true; // RIGHT-TO-LEFT EMBEDDING
        if (val == 0x202C) return true; // POP DIRECTIONAL FORMATTING
        if (val == 0x202D) return true; // LEFT-TO-RIGHT OVERRIDE
        if (val == 0x202E) return true; // RIGHT-TO-LEFT OVERRIDE
        if (val == 0x206A) return true; // INHIBIT SYMMETRIC SWAPPING
        if (val == 0x206B) return true; // ACTIVATE SYMMETRIC SWAPPING
        if (val == 0x206C) return true; // INHIBIT ARABIC FORM SHAPING
        if (val == 0x206D) return true; // ACTIVATE ARABIC FORM SHAPING
        if (val == 0x206E) return true; // NATIONAL DIGIT SHAPES
        if (val == 0x206F) return true; // NOMINAL DIGIT SHAPES

        // C.3
        if (val >= 0xE000 && val <= 0xF8FF) return true; // [PRIVATE USE, PLANE 0]
        if (val >= 0xF0000 && val <= 0xFFFFD) return true; // [PRIVATE USE, PLANE 15]
        if (val >= 0x100000 && val <= 0x10FFFD) return true; // [PRIVATE USE, PLANE 16]

        // C.4
        if (val >= 0xFDD0 && val <= 0xFDEF) return true; // [NONCHARACTER CODE POINTS]
        if (val >= 0xFFFE && val <= 0xFFFF) return true; // [NONCHARACTER CODE POINTS]
        if (val >= 0x1FFFE && val <= 0x1FFFF) return true; // [NONCHARACTER CODE POINTS]
        if (val >= 0x2FFFE && val <= 0x2FFFF) return true; // [NONCHARACTER CODE POINTS]
        if (val >= 0x3FFFE && val <= 0x3FFFF) return true; // [NONCHARACTER CODE POINTS]
        if (val >= 0x4FFFE && val <= 0x4FFFF) return true; // [NONCHARACTER CODE POINTS]
        if (val >= 0x5FFFE && val <= 0x5FFFF) return true; // [NONCHARACTER CODE POINTS]
        if (val >= 0x6FFFE && val <= 0x6FFFF) return true; // [NONCHARACTER CODE POINTS]
        if (val >= 0x7FFFE && val <= 0x7FFFF) return true; // [NONCHARACTER CODE POINTS]
        if (val >= 0x8FFFE && val <= 0x8FFFF) return true; // [NONCHARACTER CODE POINTS]
        if (val >= 0x9FFFE && val <= 0x9FFFF) return true; // [NONCHARACTER CODE POINTS]
        if (val >= 0xAFFFE && val <= 0xAFFFF) return true; // [NONCHARACTER CODE POINTS]
        if (val >= 0xBFFFE && val <= 0xBFFFF) return true; // [NONCHARACTER CODE POINTS]
        if (val >= 0xCFFFE && val <= 0xCFFFF) return true; // [NONCHARACTER CODE POINTS]
        if (val >= 0xDFFFE && val <= 0xDFFFF) return true; // [NONCHARACTER CODE POINTS]
        if (val >= 0xEFFFE && val <= 0xEFFFF) return true; // [NONCHARACTER CODE POINTS]
        if (val >= 0xFFFFE && val <= 0xFFFFF) return true; // [NONCHARACTER CODE POINTS]
        if (val >= 0x10FFFE && val <= 0x10FFFF) return true; // [NONCHARACTER CODE POINTS]

        // C.5
        if (val >= 0xD800 && val <= 0xDFFF) return true; // [SURROGATE CODES]

        // REPLACEMENT CHARACTER
        if (val == 0xFFFD) return true;

        return false;
    }

    void LDAPMatcher::insignificantSpaceHandling(std::u32string* str) {
        size_t prev_idx = 0;
        for (;;) {
            auto idx = str->find_first_not_of(0x20, prev_idx);
            if (idx == std::u32string::npos) {
                str->replace(
                    prev_idx, str->length() - prev_idx,
                    prev_idx == 0 ? 2 : 1, 0x20);
                break;
            }

            str->replace(
                prev_idx, idx - prev_idx,
                prev_idx == 0 ? 1 : 2, 0x20);

            prev_idx = str->find_first_of(0x20, prev_idx + (prev_idx == 0 ? 1 : 2));
            if (prev_idx == std::u32string::npos) {
                prev_idx = str->length();
            }
        }
    }

}
}