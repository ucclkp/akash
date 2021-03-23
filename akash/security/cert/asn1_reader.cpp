// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "akash/security/cert/asn1_reader.h"

#include <cassert>

#include "utils/stream_utils.h"

#define READ_ASN1_STREAM(mem, size)  \
    if (!checkRange(size)) return false;  \
    READ_STREAM(mem, size)


namespace akash {
namespace cert {

    ASN1Reader::ASN1Reader(std::istream& s)
        : stream_(s) {
    }

    ASN1Reader::~ASN1Reader() {
        assert(stack_.empty());
    }

    bool ASN1Reader::beginSequence() {
        ValueInfo info;
        if (!nextValue(&info)) {
            return false;
        }

        if (info.tc != TagClass::Universal || !info.is_constructed) {
            return false;
        }

        auto tag = getUniversalTag(info.tag_num);
        if (tag != UniversalTags::SequenceAndOf) {
            return false;
        }

        pushBlock(info.length, info.is_indef);
        return true;
    }

    void ASN1Reader::endSequence() {
        popBlock();
    }

    bool ASN1Reader::beginSet() {
        ValueInfo info;
        if (!nextValue(&info)) {
            return false;
        }

        if (info.tc != TagClass::Universal || !info.is_constructed) {
            return false;
        }

        auto tag = getUniversalTag(info.tag_num);
        if (tag != UniversalTags::SetAndOf) {
            return false;
        }

        pushBlock(info.length, info.is_indef);
        return true;
    }

    void ASN1Reader::endSet() {
        popBlock();
    }

    bool ASN1Reader::beginContextSpecific(uint64_t check_tag_num) {
        ValueInfo info;
        if (!nextValue(&info)) {
            return false;
        }

        if (info.tc != TagClass::ContextSpecific || !info.is_constructed) {
            return false;
        }

        if (info.tag_num != check_tag_num) {
            return false;
        }

        pushBlock(info.length, info.is_indef);
        return true;
    }

    void ASN1Reader::endContextSpecific() {
        popBlock();
    }

    bool ASN1Reader::isOutOfBounds() const {
        return !checkRange(0);
    }

    bool ASN1Reader::nextValue() {
        ValueInfo info;
        return nextValue(&info);
    }

    bool ASN1Reader::nextValue(ValueInfo* info) {
        auto& s = stream_;

        // Identifier octets
        uint8_t id_head;
        READ_ASN1_STREAM(id_head, 1);

        info->tc = TagClass(id_head >> 6);
        info->is_constructed = (id_head & 0x20);
        bool has_more_octets = (id_head & 0x1F) == 0x1F;

        uint64_t tag_number = 0;
        if (has_more_octets) {
            uint8_t next;
            uint8_t count = 0;
            do {
                READ_ASN1_STREAM(next, 1);
                tag_number <<= 7;
                tag_number |= next & 0x7F;

                ++count;
                assert(count < 10);
                if (count >= 10) {
                    return false;
                }
            } while (next & 0x80);
        } else {
            tag_number = id_head & 0x1F;
        }

        info->tag_num = tag_number;

        // Length octets
        uint8_t length_head;
        READ_ASN1_STREAM(length_head, 1);
        bool is_long_form = length_head & 0x80;
        bool is_indefinite_form = false;

        uint64_t len = 0;
        if (is_long_form) {
            uint8_t next_bytes = length_head & 0x7F;
            is_indefinite_form = next_bytes == 0;

            assert(next_bytes <= 8);
            if (next_bytes > 8) {
                return false;
            }

            for (uint8_t i = 0; i < next_bytes; ++i) {
                uint8_t next;
                READ_ASN1_STREAM(next, 1);
                len <<= 8;
                len |= next;
            }
        } else {
            len = length_head & 0x7F;
        }

        info->is_indef = is_indefinite_form;
        info->length = len;
        return true;
    }

    bool ASN1Reader::getBoolean(bool* val) {
        auto& s = stream_;
        uint8_t cur;
        READ_ASN1_STREAM(cur, 1);
        *val = cur != 0;
        return true;
    }

    bool ASN1Reader::getOctetString(const ValueInfo& info, std::string* str) {
        auto& s = stream_;

        if (!info.is_constructed) {
            return getContentBytes(info.length, info.is_indef, str);
        }

        pushBlock(info.length, info.is_indef);

        while (!isOutOfBounds()) {
            if (info.is_indef) {
                uint16_t buf;
                READ_ASN1_STREAM(buf, 2);
                if (buf == 0) { break; }
                s.seekg(-2, std::ios::cur);
            }

            std::string tmp;
            if (!getNextAsOctetString(UniversalTags::OctetString, &tmp)) {
                return false;
            }
            str->append(tmp);
        }

        popBlock();
        return true;
    }

    bool ASN1Reader::getBitString(const ValueInfo& info, std::string* str, uint8_t* unused) {
        auto& s = stream_;

        if (!info.is_constructed) {
            READ_ASN1_STREAM(*unused, 1);
            if (info.length == 0) return true;
            return getContentBytes(info.length - 1, info.is_indef, str);
        }

        pushBlock(info.length, info.is_indef);

        while (!isOutOfBounds()) {
            if (info.is_indef) {
                uint16_t buf;
                READ_ASN1_STREAM(buf, 2);
                if (buf == 0) { break; }
                s.seekg(-2, std::ios::cur);
            }

            std::string tmp;
            if (!getNextAsBitString(UniversalTags::BitString, &tmp, unused)) {
                return false;
            }
            str->append(tmp);
        }

        popBlock();
        return true;
    }

    bool ASN1Reader::getNextAsInteger(uint64_t* val) {
        auto& s = stream_;

        ValueInfo info;
        if (!nextValue(&info)) {
            return false;
        }

        if (info.tc != TagClass::Universal || info.is_constructed) {
            return false;
        }

        auto tag = getUniversalTag(info.tag_num);
        if (tag != UniversalTags::Integer) {
            return false;
        }

        uint64_t out = 0;
        if (info.is_indef) {
            uint8_t count = 0;
            bool prev = false;
            for (;;) {
                uint8_t cur;
                READ_ASN1_STREAM(cur, 1);
                if (prev && (cur == 0)) {
                    out >>= 8;
                    break;
                }
                out <<= 8;
                out |= cur;
                prev = (cur == 0);

                ++count;
                assert(count <= 8);
                if (count > 8) return false;
            }
        } else {
            assert(info.length <= 8);
            if (info.length > 8) return false;

            for (uint64_t i = 0; i < info.length; ++i) {
                out <<= 8;
                uint8_t buf;
                READ_ASN1_STREAM(buf, 1);
                out |= buf;
            }
        }

        *val = out;
        return true;
    }

    bool ASN1Reader::getNextAsBigInteger(std::string* bytes) {
        ValueInfo info;
        if (!nextValue(&info)) {
            return false;
        }

        if (info.tc != TagClass::Universal || info.is_constructed) {
            return false;
        }

        auto tag = getUniversalTag(info.tag_num);
        if (tag != UniversalTags::Integer) {
            return false;
        }

        return getContentBytes(info.length, info.is_indef, bytes);
    }

    bool ASN1Reader::getNextAsObjectID(ObjectID* obj_id) {
        auto& s = stream_;

        ValueInfo info;
        if (!nextValue(&info)) {
            return false;
        }

        if (info.tc != TagClass::Universal || info.is_constructed) {
            return false;
        }

        auto tag = getUniversalTag(info.tag_num);
        if (tag != UniversalTags::ObjectId) {
            return false;
        }

        uint8_t count = 0;
        uint64_t subid = 0;
        if (info.is_indef) {
            bool prev = false;
            for (;;) {
                uint8_t cur;
                READ_ASN1_STREAM(cur, 1);
                if (prev && (cur == 0)) {
                    subid >>= 8;
                    break;
                }
                subid <<= 7;
                subid |= cur & 0x7F;
                prev = (cur == 0);

                ++count;
                assert(count < 10);
                if (count >= 10) return false;

                if (!(cur & 0x80)) {
                    obj_id->push_back(subid);
                    subid = 0;
                    count = 0;
                }
            }
        } else {
            for (uint64_t i = 0; i < info.length; ++i) {
                subid <<= 7;
                uint8_t cur;
                READ_ASN1_STREAM(cur, 1);
                subid |= cur & 0x7F;

                ++count;
                assert(count < 10);
                if (count >= 10) return false;

                if (!(cur & 0x80)) {
                    obj_id->push_back(subid);
                    subid = 0;
                    count = 0;
                }
            }
        }

        return true;
    }

    bool ASN1Reader::getNextAsAny(std::string* any, ValueInfo* info) {
        if (!nextValue(info)) {
            return false;
        }

        return getContentBytes(info->length, info->is_indef, any);
    }

    bool ASN1Reader::getNextAsOctetString(UniversalTags check_tag, std::string* str) {
        auto& s = stream_;

        ValueInfo info;
        if (!nextValue(&info)) {
            return false;
        }

        if (info.tc != TagClass::Universal) {
            return false;
        }

        auto tag = getUniversalTag(info.tag_num);
        if (tag != check_tag) {
            return false;
        }

        if (!info.is_constructed) {
            return getContentBytes(info.length, info.is_indef, str);
        }

        pushBlock(info.length, info.is_indef);

        while (!isOutOfBounds()) {
            if (info.is_indef) {
                uint16_t buf;
                READ_ASN1_STREAM(buf, 2);
                if (buf == 0) { break; }
                s.seekg(-2, std::ios::cur);
            }

            std::string tmp;
            if (!getNextAsOctetString(UniversalTags::OctetString, &tmp)) {
                return false;
            }
            str->append(tmp);
        }

        popBlock();
        return true;
    }

    bool ASN1Reader::getNextAsBitString(UniversalTags check_tag, std::string* str, uint8_t* unused) {
        auto& s = stream_;

        ValueInfo info;
        if (!nextValue(&info)) {
            return false;
        }

        if (info.tc != TagClass::Universal) {
            return false;
        }

        auto tag = getUniversalTag(info.tag_num);
        if (tag != check_tag) {
            return false;
        }

        if (!info.is_constructed) {
            READ_ASN1_STREAM(*unused, 1);
            if (info.length == 0) return true;
            return getContentBytes(info.length - 1, info.is_indef, str);
        }

        pushBlock(info.length, info.is_indef);

        while (!isOutOfBounds()) {
            if (info.is_indef) {
                uint16_t buf;
                READ_ASN1_STREAM(buf, 2);
                if (buf == 0) { break; }
                s.seekg(-2, std::ios::cur);
            }

            std::string tmp;
            if (!getNextAsBitString(UniversalTags::BitString, &tmp, unused)) {
                return false;
            }
            str->append(tmp);
        }

        popBlock();
        return true;
    }

    bool ASN1Reader::getNextAsTime(std::string* str, bool* is_utc) {
        auto& s = stream_;

        ValueInfo info;
        if (!nextValue(&info)) {
            return false;
        }

        if (info.tc != TagClass::Universal) {
            return false;
        }

        auto tag = getUniversalTag(info.tag_num);
        if (tag != UniversalTags::UTCTime && tag != UniversalTags::GeneralizedTime) {
            return false;
        }

        *is_utc = tag == UniversalTags::UTCTime;

        if (!info.is_constructed) {
            return getContentBytes(info.length, info.is_indef, str);
        }

        pushBlock(info.length, info.is_indef);

        while (!isOutOfBounds()) {
            if (info.is_indef) {
                uint16_t buf;
                READ_ASN1_STREAM(buf, 2);
                if (buf == 0) { break; }
                s.seekg(-2, std::ios::cur);
            }

            std::string tmp;
            if (!getNextAsOctetString(UniversalTags::OctetString, &tmp)) {
                return false;
            }
            str->append(tmp);
        }

        popBlock();
        return true;
    }

    bool ASN1Reader::getContentBytes(uint64_t length, bool is_indef, std::string* bytes) {
        auto& s = stream_;

        if (is_indef) {
            bool prev = false;
            for (;;) {
                uint8_t cur;
                READ_ASN1_STREAM(cur, 1);
                if (prev && (cur == 0)) {
                    break;
                }
                bytes->push_back(cur);
                prev = (cur == 0);
            }
        } else {
            for (uint64_t i = 0; i < length; ++i) {
                uint8_t buf;
                READ_ASN1_STREAM(buf, 1);
                bytes->push_back(buf);
            }
        }
        return true;
    }

    void ASN1Reader::pushBlock(uint64_t length, bool is_indef) {
        Record rec;
        rec.is_indef = is_indef;
        rec.length = length;
        if (!is_indef) {
            rec.end = uint64_t(stream_.tellg()) + length;
        }
        stack_.push(std::move(rec));
    }

    void ASN1Reader::popBlock() {
        assert(!stack_.empty());
        if (!stack_.empty()) {
            stack_.pop();
        }
    }

    bool ASN1Reader::checkRange(uint64_t will_read_len) const {
        if (!stack_.empty()) {
            auto& top = stack_.top();
            if (!top.is_indef) {
                if (will_read_len == 0) {
                    if (uint64_t(stream_.tellg()) >= top.end) {
                        return false;
                    }
                    return true;
                }

                if (uint64_t(stream_.tellg()) + will_read_len > top.end) {
                    return false;
                }
                return true;
            }
        } else {
            auto ch = stream_.peek();
            if (!stream_) {
                return false;
            }
            if (ch == EOF) {
                return false;
            }
        }
        return true;
    }

    // static
    ASN1Reader::UniversalTags ASN1Reader::getUniversalTag(uint64_t val) {
        if (val >= uint64_t(UniversalTags::ReservedForAddenda)) {
            return UniversalTags::ReservedForAddenda;
        }
        return UniversalTags(val);
    }

}
}