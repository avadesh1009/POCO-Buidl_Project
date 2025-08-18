#ifndef MX_DEFINES_H
#define MX_DEFINES_H 

//System include
#include <iostream>
#include <string>
#include <map>

//Matrix Common Files
#include "mx_types.h"

#define SOM mx_char(1)
#define EOM mx_char(4)
#define SOT mx_char(2)
#define EOT mx_char(3)
#define SOI mx_char(28)
#define EOI mx_char(29)
#define FSP mx_char(30)
#define FVS mx_char(31)

#define SET_CMD "SET_CMD"
#define RPL_CMD "RPL_CMD"

#define GET_CFG "GET_CFG"
#define SET_CNF "SET_CNF"
#define DEF_CFG "DEF_CFG"
#define RPL_CFG "RPL_CFG"


#define UNKNOWN_STATUS_CODE  -1

using mx_DataColumn            = std::map<mx_uint64, std::string>;                // fieldId → value
using mx_DataRecord            = std::map<mx_uint64, mx_DataColumn>;              // recordIndex → FieldMap


#endif // MX_DEFINES_H
