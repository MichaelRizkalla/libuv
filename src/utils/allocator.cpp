#include "uv-common.h"

#pragma once

template <class TDataType>
TDataType create_struct(size_t count, size_t size){
    auto var = uv__calloc(count, size);
    auto data = new (var) TDataType{};

    return data;
}