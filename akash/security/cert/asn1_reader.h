// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef AKASH_SECURITY_CERT_ASN1_READER_H_
#define AKASH_SECURITY_CERT_ASN1_READER_H_

#include <stack>
#include <string>
#include <vector>


namespace akash {
namespace cert {

    class ASN1Reader {
    public:
        using ObjectID = std::vector<uint64_t>;

        enum class TagClass : uint8_t {
            Universal = 0,
            Application = 1,
            ContextSpecific = 2,
            Private = 3,
        };

        enum class UniversalTags {
            ReservedForER = 0,
            Boolean = 1,
            Integer = 2,
            BitString = 3,
            OctetString = 4,
            Null = 5,
            ObjectId = 6,
            ObjectDesc = 7,
            ExternalAndInstOf = 8,
            Real = 9,
            Enumerate = 10,
            Embedded_pdv = 11,
            UTF8String = 12,
            RelativeObjectId = 13,
            Time = 14,
            ReservedForFuture = 15,
            SequenceAndOf = 16,
            SetAndOf = 17,
            NumbericString = 18,
            PrintableString = 19,
            TeletexString = 20,
            VideotexString = 21,
            IA5String = 22,
            UTCTime = 23,
            GeneralizedTime = 24,
            GraphicString = 25,
            VisibleString = 26,
            GeneralString = 27,
            UniversalString = 28,
            UnrestrictedString = 29,
            BMPString = 30,
            Date = 31,
            TimeOfDay = 32,
            DateTime = 33,
            Duration = 34,
            OID_IRI = 35,
            RelativeOID_IRI = 36,
            ReservedForAddenda = 37, // ->
        };

        struct ValueInfo {
            TagClass tc;
            bool is_constructed;
            uint64_t tag_num;
            uint64_t length;
            bool is_indef;
        };

        explicit ASN1Reader(std::istream& s);
        ~ASN1Reader();

        bool beginSequence();
        void endSequence();

        bool beginSet();
        void endSet();

        bool beginContextSpecific(uint64_t check_tag_num);
        void endContextSpecific();

        bool isOutOfBounds() const;

        bool nextValue();
        bool nextValue(ValueInfo* info);

        bool getBoolean(bool* val);
        bool getOctetString(const ValueInfo& info, std::string* str);
        bool getBitString(const ValueInfo& info, std::string* str, uint8_t* unused);

        bool getNextAsInteger(uint64_t* val);
        bool getNextAsBigInteger(std::string* bytes);
        bool getNextAsObjectID(ObjectID* obj_id);
        bool getNextAsAny(std::string* any, ValueInfo* info);
        bool getNextAsOctetString(UniversalTags check_tag, std::string* str);
        bool getNextAsBitString(UniversalTags check_tag, std::string* str, uint8_t* unused);
        bool getNextAsTime(std::string* str, bool* is_utc);

        bool getContentBytes(uint64_t length, bool is_indef, std::string* bytes);

        static UniversalTags getUniversalTag(uint64_t val);

    private:
        struct Record {
            bool is_indef = false;
            uint64_t length = 0;
            uint64_t end = 0;
        };

        void pushBlock(uint64_t length, bool is_indef);
        void popBlock();

        bool checkRange(uint64_t will_read_len) const;

        std::istream& stream_;
        std::stack<Record> stack_;
    };

}
}

#endif  // AKASH_SECURITY_CERT_ASN1_READER_H_