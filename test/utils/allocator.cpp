#include <memory>

#pragma once

template <class TDataType>
auto test_create_ptrstruct(size_t size){
    auto *var = malloc(size);
    return new (var) TDataType{};
}

template <class TDataType>
auto test_create_ptrstruct(size_t count, size_t size){
    auto *var = calloc(count, size);
    return new (var) TDataType{};
}