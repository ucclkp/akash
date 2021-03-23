// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of akash project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "int_array.h"

#include <algorithm>
#include <memory>

#define MP_PREC  4


namespace utl {

    IntArray::IntArray()
        : buf_(new Digit[MP_PREC]()),
          used_(0),
          alloc_(MP_PREC),
          is_minus_(false) {}

    IntArray::IntArray(int alloc)
        : buf_(new Digit[alloc + MP_PREC * 2 - alloc % MP_PREC]()),
          used_(0),
          alloc_(alloc + MP_PREC * 2 - alloc % MP_PREC),
          is_minus_(false) {}

    IntArray::IntArray(const IntArray& rhs)
        : buf_(new Digit[rhs.alloc_]),
          used_(rhs.used_),
          alloc_(rhs.alloc_),
          is_minus_(rhs.is_minus_)
    {
        std::memcpy(buf_, rhs.buf_, alloc_ * sizeof(Digit));
    }

    IntArray::IntArray(IntArray&& rhs) noexcept
        : buf_(rhs.buf_), used_(rhs.used_), alloc_(rhs.alloc_), is_minus_(rhs.is_minus_)
    {
        rhs.buf_ = nullptr;
    }

    IntArray::~IntArray() {
        delete[] buf_;
    }

    IntArray& IntArray::operator=(const IntArray& rhs) {
        if (this == &rhs) {
            return *this;
        }
        if (alloc_ < rhs.used_) {
            grow(rhs.used_);
        }
        std::memcpy(buf_, rhs.buf_, rhs.used_ * sizeof(Digit));

        for (auto i = rhs.used_; i < used_; ++i) {
            buf_[i] = 0;
        }

        used_ = rhs.used_;
        is_minus_ = rhs.is_minus_;
        return *this;
    }

    IntArray& IntArray::operator=(IntArray&& rhs) noexcept {
        delete[] buf_;

        buf_ = rhs.buf_;
        used_ = rhs.used_;
        alloc_ = rhs.alloc_;
        is_minus_ = rhs.is_minus_;

        rhs.buf_ = nullptr;
        return *this;
    }

    void IntArray::swap(IntArray* rhs) {
        auto r_buf = rhs->buf_;
        auto r_used = rhs->used_;
        auto r_alloc = rhs->alloc_;
        auto r_is_minus = rhs->is_minus_;

        rhs->buf_ = buf_;
        rhs->used_ = used_;
        rhs->alloc_ = alloc_;
        rhs->is_minus_ = is_minus_;

        buf_ = r_buf;
        used_ = r_used;
        alloc_ = r_alloc;
        is_minus_ = r_is_minus;
    }

    void IntArray::grow(int size) {
        if (alloc_ >= size) {
            return;
        }

        size += MP_PREC * 2 - size % MP_PREC;
        auto prev_buf = buf_;

        buf_ = new Digit[size];
        std::memcpy(buf_, prev_buf, alloc_ * sizeof(Digit));

        delete[] prev_buf;

        for (auto i = alloc_; i < size; ++i) {
            buf_[i] = 0;
        }
        alloc_ = size;
    }

    void IntArray::shrink() {
        while (used_ > 0 && buf_[used_ - 1] == 0) {
            --used_;
        }
        if (used_ == 0) {
            is_minus_ = false;
        }
    }

    void IntArray::zero() {
        used_ = 0;
        is_minus_ = false;
        for (int i = 0; i < alloc_; ++i) {
            buf_[i] = 0;
        }
    }

    void IntArray::abs() {
        is_minus_ = false;
    }

    void IntArray::inv() {
        if (isZero()) {
            return;
        }
        is_minus_ = !is_minus_;
    }

    void IntArray::destroy() {
        for (int i = 0; i < used_; ++i) {
            buf_[i] = 0;
        }
        used_ = 0;
        is_minus_ = false;
    }

    bool IntArray::isOdd() const {
        return buf_[0] & Digit(1);
    }

    bool IntArray::isZero() const {
        return used_ == 0;
    }

    bool IntArray::isMinus() const {
        return is_minus_;
    }

}
