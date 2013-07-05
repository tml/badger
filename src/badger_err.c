#include "badger_err.h"
#include <tomcrypt.h>

static bdgr_err bdgr_last_err;
static int bdgr_last_err_line;
static int bdgr_last_crypt_err = CRYPT_OK;
static json_error_t bdgr_g_json_error;
static char bdgr_error_string_buffer[2048];
static char bdgr_json_error_string_buffer[1024];

int bdgr_error()
{
    return (int)bdgr_last_err;
}

int bdgr_check( const int ret, const bdgr_err err, const int line )
{
    if( ret ) {
        bdgr_last_err = err;
        bdgr_last_err_line = line;
    } else {
        bdgr_last_err = bdgr_no_err;
    }
    return ret;
}

int bdgr_crypt( const int ret, const int line )
{
    if( ret != CRYPT_OK ) {
        bdgr_check( ret, bdgr_crypt_err, line );
    }
    return bdgr_last_crypt_err = ret;
}

json_error_t *bdgr_json_error()
{
    return &bdgr_g_json_error;
}

static const char* bdgr_short_error_string( const int err )
{
    switch( err ) {
    case bdgr_no_err:
        return "No error occurred";
    case bdgr_malloc_err:
        return "Out of memory";
    case bdgr_crypt_err:
        return error_to_string( bdgr_last_crypt_err );
    case bdgr_register_prng_err:
        return "Failed to register PRNG";
    case bdgr_json_load_err:
        sprintf( bdgr_json_error_string_buffer,
                 "Failed to load JSON string: %s",
                 bdgr_json_error()->text );
        return bdgr_json_error_string_buffer;
    case bdgr_json_pack_err:
        return "Failed to pack JSON values";
    case bdgr_json_dump_err:
        return "Failed to dump JSON string";
    case bdgr_json_dsa_missing_err:
        return "Record missing dsa attribute";
    case bdgr_json_dsa_not_string_err:
        return "Record dsa not a string";
    case bdgr_json_dsa_err:
        return "Failed to allocate dsa string";
    case bdgr_json_id_missing_err:
        return "Badge missing id attribute";
    case bdgr_json_id_not_string_err:
        return "Badge id not a string";
    case bdgr_json_id_err:
        return "Failed to allocate id string";
    case bdgr_json_token_missing_err:
        return "Badge missing token attribute";
    case bdgr_json_token_not_string_err:
        return "Badge token not a string";
    case bdgr_json_token_err:
        return "Failed to allocate token string";
    case bdgr_json_signature_missing_err:
        return "Badge missing signature attribute";
    case bdgr_json_signature_not_string_err:
        return "Badge signature not a string";
    case bdgr_json_signature_err:
        return "Failed to allocate signature string";
    case bdgr_rpc_result_missing_err:
        return "Invalid RPC response (missing result attribute)";
    case bdgr_rpc_result_null_err:
        return "Name not found";
    case bdgr_rpc_result_not_object_err:
        return "Invalid RPC response "
            "(result is not null and not an object)";
    case bdgr_rpc_value_missing_err:
        return "Invalid RPC response (missing value attribute)";
    case bdgr_rpc_value_not_string_err:
        return "Invalid RPC response (value not a string)";
    case bdgr_rpc_value_err:
        return "Failed to allocate value string";
    case bdgr_password_len_err:
        return "Password cannot be more than 64 characters";
    case bdgr_unsupported_scheme_err:
        return "Unsupported id scheme";
    }
    return "";
}

const char* bdgr_error_string( const int err )
{
    const char* string = bdgr_short_error_string( err );
#ifndef NDEBUG
    sprintf( bdgr_error_string_buffer,
             "%s (line %d)", string, bdgr_last_err_line );
    return bdgr_error_string_buffer;
#endif
    return string;
}
