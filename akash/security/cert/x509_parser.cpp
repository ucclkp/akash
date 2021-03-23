// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/security/cert/x509_parser.h"


namespace akash {
namespace cert {
namespace x509 {

    X509Parser::X509Parser() {}

    bool X509Parser::parse(std::istream& s, Certificate* out) {
        ASN1Reader reader(s);
        if (reader.beginSequence()) {
            if (!parseTBSCertificate(reader, &out->tbs_certificate)) {
                return false;
            }

            if (!parseAlgorithmIdentifier(reader, &out->signature_algorithm)) {
                return false;
            }

            if (!reader.getNextAsBitString(
                ASN1Reader::UniversalTags::BitString, &out->signature_value, &out->sv_unused))
            {
                return false;
            }

            reader.endSequence();
        }

        /*if (!reader.isOutOfBounds()) {
            return false;
        }*/
        return true;
    }

    bool X509Parser::parseTBSCertificate(ASN1Reader& reader, TBSCertificate* out) {
        if (reader.beginSequence()) {
            // version 被标记为 DEFAULT，根据 X.680 25.11，
            // 该字段可能没有。因此先看下第一个值的相关元数据。
            ASN1Reader::ValueInfo info;
            if (!reader.nextValue(&info)) {
                return false;
            }
            // 看下是否存在 version
            if (info.tc == ASN1Reader::TagClass::ContextSpecific) {
                if (info.tag_num != 0 || !info.is_constructed) {
                    return false;
                }

                uint64_t ver;
                if (!reader.getNextAsInteger(&ver)) {
                    return false;
                }
                out->version = Version(ver);
            }

            if (!reader.getNextAsBigInteger(&out->serial_number)) {
                return false;
            }
            if (!parseAlgorithmIdentifier(reader, &out->signature)) {
                return false;
            }
            if (!parseName(reader, &out->issuer)) {
                return false;
            }

            // Validity
            {
                if (!reader.beginSequence()) {
                    return false;
                }

                Time not_before;
                std::string nb_str;
                if (!reader.getNextAsTime(&nb_str, &not_before.is_utc)) {
                    return false;
                }
                if (not_before.is_utc) {
                    not_before.utc_time = std::move(nb_str);
                } else {
                    not_before.general_time = std::move(nb_str);
                }
                out->validity.not_before = std::move(not_before);

                Time not_after;
                std::string na_str;
                if (!reader.getNextAsTime(&na_str, &not_after.is_utc)) {
                    return false;
                }
                if (not_after.is_utc) {
                    not_after.utc_time = std::move(na_str);
                } else {
                    not_after.general_time = std::move(na_str);
                }
                out->validity.not_after = std::move(not_after);

                reader.endSequence();
            }

            if (!parseName(reader, &out->subject)) {
                return false;
            }

            // SubjectPublicKeyInfo
            {
                if (!reader.beginSequence()) {
                    return false;
                }

                SubjectPublicKeyInfo key_info;
                if (!parseAlgorithmIdentifier(reader, &key_info.algorithm)) {
                    return false;
                }

                if (!reader.getNextAsBitString(
                    ASN1Reader::UniversalTags::BitString,
                    &key_info.subject_public_key, &key_info.spk_unused))
                {
                    return false;
                }

                out->subject_public_key_info = std::move(key_info);

                reader.endSequence();
            }

            uint8_t cur_step = 0;
            // 接下来的三个字段都被标为 OPTIONAL，根据 X.680 25.11，
            // 这几个字段可能没有。
            while (!reader.isOutOfBounds()) {
                if (!reader.nextValue(&info)) {
                    return false;
                }
                if (info.tc != ASN1Reader::TagClass::ContextSpecific) {
                    return false;
                }

                if (info.tag_num == 1) {
                    // 第一个 OPTIONAL
                    if (cur_step != 0) {
                        return false;
                    }
                    if (!reader.getBitString(info, &out->issuer_unique_id, &out->iui_unused)) {
                        return false;
                    }
                    cur_step = 1;
                } else if (info.tag_num == 2) {
                    // 第二个 OPTIONAL
                    if (cur_step > 1) {
                        return false;
                    }
                    if (!reader.getBitString(info, &out->subject_unique_id, &out->sui_unused)) {
                        return false;
                    }
                    cur_step = 2;
                } else if(info.tag_num == 3) {
                    // 第三个 OPTIONAL
                    if (cur_step == 3) {
                        return false;
                    }
                    if (!reader.beginSequence()) {
                        return false;
                    }

                    while (!reader.isOutOfBounds()) {
                        if (!reader.beginSequence()) {
                            return false;
                        }

                        Extension ext;
                        if (!reader.getNextAsObjectID(&ext.extn_id)) {
                            return false;
                        }

                        // critical 字段可能没有，于是要检查下 tag_num
                        if (!reader.nextValue(&info)) {
                            return false;
                        }
                        if (info.tc != ASN1Reader::TagClass::Universal) {
                            return false;
                        }

                        auto tag = ASN1Reader::getUniversalTag(info.tag_num);
                        if (tag == ASN1Reader::UniversalTags::Boolean) {
                            if (!reader.getBoolean(&ext.critical)) {
                                return false;
                            }
                            if (!reader.getNextAsOctetString(
                                ASN1Reader::UniversalTags::OctetString, &ext.extn_value))
                            {
                                return false;
                            }
                        } else if (tag == ASN1Reader::UniversalTags::OctetString) {
                            if (!reader.getOctetString(info, &ext.extn_value)) {
                                return false;
                            }
                        } else {
                            return false;
                        }

                        out->extensions.push_back(std::move(ext));

                        reader.endSequence();
                    }

                    reader.endSequence();
                    cur_step = 3;
                } else {
                    return false;
                }
            }

            reader.endSequence();
        }
        return true;
    }

    bool X509Parser::parseName(ASN1Reader& reader, Name* out) {
        if (!reader.beginSequence()) {
            return false;
        }

        while (!reader.isOutOfBounds()) {
            std::vector<AttributeTypeAndValue> attrs;
            if (!reader.beginSet()) {
                return false;
            }

            do {
                if (!reader.beginSequence()) {
                    return false;
                }

                AttributeTypeAndValue attr;
                if (!reader.getNextAsObjectID(&attr.type)) {
                    return false;
                }
                ASN1Reader::ValueInfo info;
                if (!reader.getNextAsAny(&attr.value, &info)) {
                    return false;
                }
                attr.val_type = ASN1Reader::UniversalTags(info.tag_num);
                attrs.push_back(std::move(attr));

                reader.endSequence();
            } while (!reader.isOutOfBounds());

            reader.endSet();
            out->rdn_sequence.push_back(std::move(attrs));
        }

        reader.endSequence();
        return true;
    }

    bool X509Parser::parseAlgorithmIdentifier(ASN1Reader& reader, AlgorithmIdentifier* out) {
        if (!reader.beginSequence()) {
            return false;
        }

        if (!reader.getNextAsObjectID(&out->algorithm)) {
            return false;
        }

        ASN1Reader::ValueInfo info;
        if (!reader.getNextAsAny(&out->parameters, &info)) {
            return false;
        }

        reader.endSequence();
        return true;
    }

}
}
}