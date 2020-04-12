#include "../uv-common.h"
#include <new>

#pragma once

template <class TDataType>
auto create_ptrstruct(size_t count, size_t size){
    auto *var = uv__calloc(count, size);
    return new (var) TDataType{};
}

template <class TDataType>
auto create_ptrstruct(size_t size){
    auto *var = uv__malloc(size);
    return new (var) TDataType{};
}

template <class TDataType>
auto create_ptrstruct_free(void* ptr, size_t size){
    auto *var = uv__reallocf(ptr, size);
    return new (var) TDataType{};
}

template <class TDataType>
auto create_ptrstruct(void* ptr, size_t size){
    auto *var = uv__realloc(ptr, size);
    return new (var) TDataType{};
}