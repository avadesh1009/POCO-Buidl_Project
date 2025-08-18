#ifndef MX_PORTABLE_TYPES_H
#define MX_PORTABLE_TYPES_H

/*
<cstdint> types are truly fixed - size across all modern compilers and platforms:
-> Guaranteed by the C++11 standard
-> Used widely in OS kernels, protocols, SDKs, drivers
-> The safest choice for cross - platform, binary - stable code
*/
// For fixed-width integer types

#include <cstdint>

// Boolean
typedef bool                mx_bool;    // boolean type

// Character types
typedef signed char         mx_char;    // signed char (1 byte)
typedef unsigned char       mx_uchar;   // unsigned char (1 byte)
typedef char16_t            mx_char16;  // UTF-16 2-byte wide char (may need conversion)
typedef char32_t            mx_char32;  // UTF-32 4-byte wide char (may need conversion)

// Integer types
typedef signed char         mx_byte;    // 1 byte signed integer
typedef unsigned char       mx_ubyte;   // 1 byte unsigned integer
typedef int16_t             mx_int16;   // 2 byte signed integer
typedef uint16_t            mx_uint16;  // 2 byte unsigned integer
typedef int32_t             mx_int32;   // 4 byte signed integer
typedef uint32_t            mx_uint32;  // 4 byte unsigned integer
typedef int64_t             mx_int64;   // 8 byte signed integer
typedef uint64_t            mx_uint64;  // 8 byte unsigned integer

// Floating point types (IEEE-754)
typedef float               mx_float;   // 4 byte floating point
typedef double              mx_double;  // 8 byte floating point


#endif // MX_PORTABLE_TYPES_H
