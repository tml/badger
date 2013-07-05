#include "badger_err.h"
#include <tomcrypt.h>

static bdgr_err bdgr_last_err;
static int bdgr_last_err_line;
static int bdgr_last_crypt_err = CRYPT_OK;
static json_error_t bdgr_g_json_error;
static char bdgr_g_error_string[1024];
static char bdgr_g_json_error_string[1024];
static char bdgr_g_rpc_error_string[1024];

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

void bdgr_rpc_error( const char* err, const int line )
{
    strncpy( bdgr_g_rpc_error_string,
             err,
             sizeof( bdgr_g_rpc_error_string ));
    bdgr_check( 1, bdgr_rpc_err, line );
}

static const char* bdgr_short_error_string( const int err )
{
    switch( err ) {
    case bdgr_no_err:
        return "No error occurred";
    case bdgr_malloc_err:
        return "Failed to malloc memory";
    case bdgr_realloc_err:
        return "Failed to realloc memory";
    case bdgr_crypt_err:
        return error_to_string( bdgr_last_crypt_err );
    case bdgr_register_prng_err:
        return "Failed to register PRNG";
    case bdgr_json_load_err:
        sprintf( bdgr_g_json_error_string,
                 "Failed to load JSON string: %s",
                 bdgr_json_error()->text );
        return bdgr_g_json_error_string;
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
    case bdgr_response_overflow:
        return "Response data overflow";
    case bdgr_json_result_missing_err:
        return "Invalid RPC response (missing result attribute)";
    case bdgr_json_result_not_object_err:
        return "Invalid RPC response "
            "(result is not null and not an object)";
    case bdgr_json_value_missing_err:
        return "Invalid RPC response (missing value attribute)";
    case bdgr_json_value_not_string_err:
        return "Invalid RPC response (value not a string)";
    case bdgr_json_value_err:
        return "Failed to allocate value string";
    case bdgr_json_error_missing_err:
        return "Invalid RPC error (missing error attribute)";
    case bdgr_json_error_not_object_err:
        return "Invalid RPC error (error is not an object)";
    case bdgr_json_error_message_missing_err:
        return "Invalid RPC error (error message missing)";
    case bdgr_json_error_message_not_string_err:
        return "Invalid RPC error (error message is not a string)";
    case bdgr_json_error_message_err:
        return "Failed to allocate RPC error message";
    case bdgr_rpc_err:
        return bdgr_g_rpc_error_string;
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
    sprintf( bdgr_g_error_string,
             "%s (line %d)", string, bdgr_last_err_line );
    return bdgr_g_error_string;
#endif
    return string;
}
