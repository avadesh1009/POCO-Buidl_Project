#ifndef MX_ERROR_CODES_H
#define MX_ERROR_CODES_H


enum class eMxErrorCode
{
    // because NO_ERROR already defined in winerror.h , we need to change NO_ERROR. At present we have temporary defined it.
    // will find proper solution for it or else replace NO_ERROR with new name at all places. 
    NO_ERR          = 0,
    
    NO_ERROR        = 0,
    UNKNOWN_ERROR   = 1,
    OUT_OF_MEMORY   = 3,
    ERR_INVALID_BUFFER = 4,

    
    ERR_INVALID_PORT                        = 100,
    ERR_INVALID_SSL_PORT                    = 101,
    ERR_INVALID_IP_RANGE                    = 102,
    ERR_SERVICE_START_FAILED                = 106,

    ERR_IPV6_NOT_SUPPORT                    = 200,
    ERR_CONNECTION_TIME_OUT                 = 201,
    ERR_CONNECTION_FAILED                   = 202,
    ERR_SOCKET_NOT_INITIALIZED              = 203,
    ERR_SOCKET_DISCONNECTED                 = 204,
    ERR_SOCKET_NOT_READY_READ               = 205,
    ERR_SOCKET_NOT_READY_WRITE              = 206,

    
    //Parser Module Erorr Code
    ERR_PARSER_INVALID_RESPONSE             = 851,
    ERR_PARSER_INVALID_SOM_EOM_INDEX        = 852,
    ERR_PARSER_INVALID_FSP_INDEX            = 853,
    ERR_PARSER_INVALID_RPL_CNG              = 854,
    ERR_PARSER_INVALID_RPL_CMD              = 855,
    ERR_PARSER_INVALID_STATUS_CODE          = 856,
    ERR_PARSER_INVALID_SOI_EOI_INDEX        = 857,
    ERR_PARSER_INVALID_INDEX_ID             = 858,
    ERR_PARSER_INVALID_SOT_EOT_INDEX        = 869,
    ERR_PARSER_INVAVID_TABLE_ID             = 860,
    ERR_PARSER_INVALID_FVS_INDEX            = 861,
    ERR_PARSER_INVALID_FIELD_ID             = 862,

};

#endif // MX_ERROR_CODES_H

