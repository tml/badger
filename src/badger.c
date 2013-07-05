/*
  Copyright 2013 John Driscoll
   
  This file is part of Badger.

  Badger is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  Badger is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with Badger.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <tomcrypt.h>
#include <jansson.h>
#include <curl/curl.h>
#include <badger.h>
#include "badger_err.h"

static int bdgr_init();

int bdgr_key_generate(
    const char* const password,
    bdgr_key* const key
)
{
    prng_state prng;
    char sane_pass[64];
    unsigned int pass_len = strlen( password );

    bdgr_init();
    if( bdgr_error() ) {
        return bdgr_error();
    }

    key->_impl = NULL;

    /* Create an rng we can seed with Alice's password */
    bdgr_check( register_prng( &rc4_desc ), bdgr_register_prng_err, __LINE__ );
    if ( bdgr_error() ) {
        goto bdgr_key_generate_free;
    }

    /* Start it */
    bdgr_crypt( rc4_start( &prng ), __LINE__ );
    if ( bdgr_error() ) {
        goto bdgr_key_generate_free;
    }

    /* Sanity check */
    bdgr_check( pass_len > sizeof( sane_pass ),
                bdgr_password_len_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_key_generate_free;
    }

    /* Copy the pass to a properly sized space */
    memcpy( sane_pass, password, pass_len );
    memset( sane_pass + pass_len, 0, sizeof( sane_pass ) - pass_len );

    /* Make sure the prng buffer starts fresh */
    memset( prng.rc4.buf, 0, 256 );

    bdgr_crypt( rc4_add_entropy(
                    (unsigned char*)sane_pass,
                    sizeof( sane_pass ),
                    &prng ),
                __LINE__ );
    if ( bdgr_error() ) {
        goto bdgr_key_generate_free;
    }
    
    bdgr_crypt( rc4_ready( &prng ), __LINE__ );
    if ( bdgr_error() ) {
        goto bdgr_key_generate_free;
    }

    key->_impl = malloc( sizeof( dsa_key ));
    bdgr_check( key->_impl == NULL, bdgr_malloc_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_key_generate_free;
    }
    
    bdgr_crypt( dsa_make_key(
                    &prng, find_prng( "rc4" ),
                    20, 128,
                    (dsa_key*)key->_impl ),
                __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_key_generate_free;
    }
    
 bdgr_key_generate_free:
    
    /* Scrub any copies of the password from memory */
    memset( prng.rc4.buf, 0, 256 );
    memset( sane_pass, 0, sizeof( sane_pass ));
    
    rc4_done( &prng );

    if( bdgr_error() && key->_impl != NULL ) {
        free( key->_impl );
    }

    return bdgr_error();
    
}

int bdgr_key_import(
    const unsigned char* const data,
    const unsigned long int data_len,
    bdgr_key* const key
)
{
    bdgr_init();
    if( bdgr_error() ) {
        return bdgr_error();
    }

    key->_impl = malloc( sizeof( dsa_key ));
    bdgr_check( key->_impl == NULL, bdgr_malloc_err, __LINE__ );
    if( bdgr_error() ) {
        return bdgr_error();
    }
    
    bdgr_crypt( dsa_import( data, data_len, (dsa_key*)key->_impl ), __LINE__ );

    return bdgr_error();
}

int bdgr_key_decode(
    const char* const string,
    bdgr_key* const key
)
{
    unsigned long int string_len = strlen( string );
    unsigned long int data_len = string_len;
    unsigned char* data = malloc( data_len );
    bdgr_check( data == NULL, bdgr_malloc_err, __LINE__ );
    if( bdgr_error() ) {
        return bdgr_error();
    }
    
    bdgr_init();
    if( bdgr_error() ) {
        return bdgr_error();
    }
    
    bdgr_crypt( base64_decode(
                    (unsigned char*)string, string_len,
                    data, &data_len ),
                __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_key_decode_free;
    }
    
    bdgr_key_import( data, data_len, key );
    
    if( bdgr_error() ) {
        goto bdgr_key_decode_free;
    }

 bdgr_key_decode_free:

    free( data );
    return bdgr_error();
}

int bdgr_key_export_public(
    const bdgr_key* const key,
    unsigned char* const data,
    unsigned long int* const data_len
)
{
    bdgr_crypt( dsa_export(
                    data, data_len, PK_PUBLIC, (dsa_key*)key->_impl ),
                __LINE__ );
    return bdgr_error();
}

int bdgr_key_export_private(
    const bdgr_key* const key,
    unsigned char* const data,
    unsigned long int* const data_len
)
{
    bdgr_crypt( dsa_export(
                    data, data_len, PK_PRIVATE, (dsa_key*)key->_impl ),
                __LINE__ );
    return bdgr_error();
}

static int bdgr_key_encode(
    const bdgr_key* const key,
    char** string,
    int type
)
{
    char* string_out;
    unsigned long int data_len = 2048, string_out_len;
    unsigned char* data = malloc( data_len );
    bdgr_check( data == NULL, bdgr_malloc_err, __LINE__ );
    if( bdgr_error() ) {
        return bdgr_error();
    }
    if( type ) {
        bdgr_crypt( bdgr_key_export_private( key, data, &data_len ), __LINE__ );
    } else {
        bdgr_crypt( bdgr_key_export_public( key, data, &data_len ), __LINE__ );
    }
    if( bdgr_error() ) {
        goto bdgr_key_encode_free;
    }
    string_out_len = (data_len * 1.37) + 815;
    string_out = malloc( string_out_len );
    bdgr_check( string_out == NULL, bdgr_malloc_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_key_encode_free;
    }
    bdgr_crypt( base64_encode(
                    data, data_len,
                    (unsigned char*)string_out, &string_out_len ),
                __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_key_encode_free;
    }
    
 bdgr_key_encode_free:

    free( data );
    if( bdgr_error() ) {
        if( string_out ) {
            free( string_out );
        }
    } else {
        if( string_out ) {
            *string = string_out;
        }
    }
    return bdgr_error();
}

int bdgr_key_encode_public(
    const bdgr_key* const key,
    char** string
)
{
    return bdgr_key_encode( key, string, 0 );
}

int bdgr_key_encode_private(
    const bdgr_key* const key,
    char** string
)
{
    return bdgr_key_encode( key, string, 1 );
}

void bdgr_key_free(
    bdgr_key* const key
)
{
    dsa_free( (dsa_key*)key->_impl );
    free( key->_impl );
}

int bdgr_token_sign(
    const unsigned char* const token,
    const unsigned long int token_len,
    const bdgr_key* const key,
    unsigned char* const signature,
    unsigned long int* const signature_len
)
{
    prng_state prng;
    
    bdgr_init();
    if( bdgr_error() ) {
        return bdgr_error();
    }

    bdgr_check( register_prng( &fortuna_desc ) == -1,
                bdgr_register_prng_err, __LINE__ );
    if( bdgr_error() ) {
        return bdgr_error();

    }
    bdgr_crypt( rng_make_prng(
                    128, find_prng("fortuna"), &prng, NULL ),
                __LINE__ );
    if( bdgr_error() ) {
        return bdgr_error();
    }
    bdgr_crypt( dsa_sign_hash(
                    token, token_len,
                    signature, signature_len,
                    &prng, find_prng( "fortuna" ),
                    (dsa_key*)key->_impl ),
                __LINE__ );
    if( bdgr_error() ) {
        return bdgr_error();
    }
    return bdgr_no_err;
}

int bdgr_badge_make(
    const char* const id,
    const unsigned char* const token,
    const unsigned long int token_len,
    const unsigned char* const signature,
    const unsigned long int signature_len,
    bdgr_badge* const badge
)
{
    unsigned long int id_len = strlen( id );
    memcpy( (void*)&badge->token_len,
            &token_len,
            sizeof( token_len ));
    memcpy( (void*)&badge->signature_len,
            &signature_len,
            sizeof( signature_len ));
    
    badge->id = malloc( id_len );
    bdgr_check( badge->id == NULL, bdgr_malloc_err, __LINE__ );
    if( bdgr_error() ) {
        return bdgr_error();
    }
    
    badge->token = malloc( token_len );
    bdgr_check( badge->token == NULL, bdgr_malloc_err, __LINE__ );
    if( bdgr_error() ) {
        free( (char*)badge->id );
        return bdgr_error();
    }
    
    badge->signature = malloc( signature_len );
    bdgr_check( badge->signature == NULL, bdgr_malloc_err, __LINE__ );
    if( bdgr_error() ) {
        free( (char*)badge->id );
        free( (char*)badge->token );
        return bdgr_error();
    }
    
    strcpy( (char*)badge->id, id );
    memcpy( (unsigned char*)badge->token, token, token_len );
    memcpy( (unsigned char*)badge->signature, signature, signature_len );
    
    return bdgr_no_err;
}

int bdgr_signature_verify(
    const unsigned char* const token,
    const unsigned long int token_len,
    const unsigned char* const signature,
    const unsigned long int signature_len,
    const bdgr_key* const key,
    int* const verified
)
{
    bdgr_init();
    if( bdgr_error() ) {
        return bdgr_error();
    }
    
    bdgr_crypt( dsa_verify_hash(
                    signature,
                    signature_len,
                    token,
                    token_len,
                    verified,
                    (dsa_key*)key->_impl ),
                __LINE__ );
    return bdgr_error();
}

int bdgr_record_import(
    const char* const record,
    bdgr_key* const key
)
{
    json_t* root, * dsa;
    const char* dsa_string;

    root = json_loads( record, 0, bdgr_json_error() );
    bdgr_check( root == NULL, bdgr_json_load_err, __LINE__ );
    if( bdgr_error() ) {
        return bdgr_error();
    }
    
    dsa = json_object_get( root, "dsa" );
    bdgr_check( dsa == NULL, bdgr_json_dsa_missing_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_record_import_free;
    }
    
    bdgr_check( !json_is_string( dsa ),
                bdgr_json_dsa_not_string_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_record_import_free;
    }

    dsa_string = json_string_value( dsa );
    bdgr_check( dsa_string == NULL, bdgr_json_dsa_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_record_import_free;
    }

    bdgr_key_decode( dsa_string, key );

 bdgr_record_import_free:
    
    json_decref( root );
    return bdgr_error();

}

struct bdgr_scheme_handler {
    char* scheme;
    int (*handle_url)( const char* const url, const char** record );
    struct bdgr_scheme_handler* next;
};

static struct bdgr_scheme_handler* bdgr_scheme_handlers = NULL;

int bdgr_badge_verify(
    const bdgr_badge* const badge,
    int* const verified
)
{
    int support_scheme;
    bdgr_key key;
    struct bdgr_scheme_handler* curr;
    const char* record;

    bdgr_init();
    if( bdgr_error() ) {
        return bdgr_error();
    }

    curr = bdgr_scheme_handlers;
    
    while( curr ) {
        if( !strncmp( badge->id, curr->scheme,
                      strlen( curr->scheme ))) {
            support_scheme = 1;

            curr->handle_url( badge->id, &record );
            if( bdgr_error() ) {
                return bdgr_error();
            }
            break;
        }
        curr = curr->next;
    }
    
    if( bdgr_check( !support_scheme,
                    bdgr_unsupported_scheme_err, __LINE__ )) {
        return bdgr_error();
    }
    
    bdgr_record_import( record, &key );
    if( bdgr_error() ) {
        return bdgr_error();
    }
    
    return bdgr_signature_verify(
        badge->token,
        badge->token_len,
        badge->signature,
        badge->signature_len,
        &key,
        verified );
}

int bdgr_badge_import(
    const char* const json_string,
    bdgr_badge* const badge
)
{
    json_t* root = NULL, * id, * token, * signature;
    json_error_t error;
    const char* tokenc = NULL, * signaturec = NULL, * idc = NULL;
    char* idc_copy;
    unsigned char* tokenb = NULL, * signatureb = NULL;
    unsigned long int tokenb_len, signatureb_len;

    root = json_loads( json_string, 0, &error );
    bdgr_check( root == NULL, bdgr_json_load_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_import_free;
    }

    id = json_object_get( root, "id" );
    bdgr_check( id == NULL, bdgr_json_id_missing_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_import_free;
    }
    
    bdgr_check( !json_is_string( id ), bdgr_json_id_not_string_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_import_free;
    }
    
    token = json_object_get( root, "token" );
    bdgr_check( token == NULL, bdgr_json_token_missing_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_import_free;
    }

    bdgr_check( !json_is_string( token ),
                bdgr_json_token_not_string_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_import_free;
    }
    
    signature = json_object_get( root, "signature" );
    bdgr_check( signature == NULL,
                bdgr_json_signature_missing_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_import_free;
    }
    
    bdgr_check( !json_is_string( signature ),
                bdgr_json_signature_not_string_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_import_free;
    }

    tokenc = json_string_value( token );
    bdgr_check( tokenc == NULL, bdgr_json_token_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_import_free;
    }
    
    tokenb_len = strlen( tokenc );
    tokenb = malloc( tokenb_len );
    bdgr_check( tokenb == NULL, bdgr_malloc_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_import_free;
    }
    
    bdgr_crypt( base64_decode(
                    (unsigned char*)tokenc, tokenb_len,
                    tokenb, &tokenb_len ),
                __LINE__ );
    if( bdgr_error() ){
        goto bdgr_badge_import_free;
    }
    
    signaturec = json_string_value( signature );
    bdgr_check( signaturec == NULL, bdgr_json_signature_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_import_free;
    }
    
    signatureb_len = strlen( signaturec );
    signatureb = malloc( signatureb_len );
    bdgr_crypt( base64_decode(
                    (unsigned char*)signaturec, signatureb_len,
                    signatureb, &signatureb_len ),
                __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_import_free;
    }

    idc = json_string_value( id );
    bdgr_check( idc == NULL, bdgr_json_id_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_import_free;
    }

    idc_copy = strdup( idc );
    bdgr_check( idc_copy == NULL, bdgr_malloc_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_import_free;
    }

    memcpy( (void*)&badge->id,
            &idc_copy, sizeof( idc_copy ));
    memcpy( (void*)&badge->token,
            &tokenb, sizeof( tokenb ));
    memcpy( (void*)&badge->token_len,
            &tokenb_len, sizeof( tokenb_len ));
    memcpy( (void*)&badge->signature,
            &signatureb, sizeof( signatureb ));
    memcpy( (void*)&badge->signature_len,
            &signatureb_len, sizeof( signatureb_len ));
    
 bdgr_badge_import_free:

    if( root != NULL ) {
        json_decref( root );
    }
    return bdgr_error();
    
}

int bdgr_badge_export(
    const bdgr_badge* const badge,
    char** json_string
)
{
    json_t* root;
    char* tokenc = NULL, * signaturec = NULL;
    unsigned long int tokenc_len, signaturec_len;
    
    tokenc_len = (badge->token_len * 1.37) + 815;
    tokenc = malloc( tokenc_len );
    bdgr_check( tokenc == NULL, bdgr_malloc_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_export_free;
    }
    
    signaturec_len = (badge->signature_len * 1.37) + 815;
    signaturec = malloc( signaturec_len );
    bdgr_check( signaturec == NULL, bdgr_malloc_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_export_free;
    }
    
    bdgr_crypt( base64_encode(
                    badge->token, badge->token_len,
                    (unsigned char*)tokenc, &tokenc_len ),
                __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_export_free;
    }
    
    bdgr_crypt( base64_encode(
                    badge->signature, badge->signature_len,
                    (unsigned char*)signaturec, &signaturec_len ),
                __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_export_free;
    }
    
    root = json_pack(
        "{ssssss}",
        "id", badge->id,
        "token", tokenc,
        "signature", signaturec );
    bdgr_check( root == NULL, bdgr_json_pack_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_badge_export_free;
    }

    *json_string = json_dumps( root, 0 );
    bdgr_check( *json_string == NULL, bdgr_json_dump_err, __LINE__ );
    
 bdgr_badge_export_free:

    if( tokenc != NULL ) {
        free( tokenc );
    }
    if( signaturec != NULL ) {
        free( signaturec );
    }
    if( root != NULL ) {
        json_decref( root );
    }
    
    return bdgr_error();
}

void bdgr_badge_free(
    bdgr_badge* const badge
)
{
    free( (char*)badge->id );
    free( (char*)badge->token );
    free( (char*)badge->signature );
}

typedef struct {
    char* data;
    unsigned long int size;
    bdgr_err error;
} bdgr_buffer;

static size_t bdgr_record_data(
    char *ptr,
    size_t size,
    size_t nmemb,
    void *_buf )
{
    bdgr_buffer *buf = (bdgr_buffer*)_buf;
    int sane_size = size*nmemb;
    if( buf->data == NULL ) {
        buf->data = malloc( sane_size );
        buf->size = 0;
        buf->error = bdgr_no_err;
        bdgr_check( buf->data == NULL, bdgr_malloc_err, __LINE__ );
    } else  {
        buf->data = realloc( buf->data, buf->size + sane_size );
        bdgr_check( buf->data == NULL, bdgr_realloc_err, __LINE__ );
    }
    if( bdgr_error() ) {
        buf->error = bdgr_error();
        return 0;
    }
    memcpy( buf->data + buf->size, ptr, sane_size );
    buf->size += sane_size;
    return size;
}

static int bdgr_scheme_nmc( const char* const url, const char** record )
{
    
    CURL* const handle = curl_easy_init();
    char* post_data;
    const char* block_name, * rpc_error;
    static const char* const rpc_fmt =
        "{\"method\":\"name_show\",\"params\":[\"%s\"]}";
    const unsigned long int rpc_fmt_len = strlen( rpc_fmt ) - 2;
    struct curl_slist *headers = NULL;
    bdgr_buffer buf;
    json_t* root, * result, * value, * error, * message;
    static char rpc_server[1024];
    static int init = 0;
    
    if( !init ) {
        
        /* Parse out rpc connection details from bitcoin.conf */
        struct passwd* pw = getpwuid( getuid() );
        char* rel_path = "/.namecoin/bitcoin.conf";
        char conf_path[256], name[256], val[256], * line = NULL, * pos;
        char* rpc_scheme = "http://";
        char rpcport[16], rpcconnect[256], rpcuser[256], rpcpass[256];
        size_t len;
        FILE* conf;

        strcpy( rpcport, "8336" );
        strcpy( rpcconnect, "127.0.0.1" );
        rpcuser[0] = '\0';
        rpcpass[0] = '\0';
        sprintf( conf_path, "%s%s", pw->pw_dir, rel_path );
        conf = fopen( conf_path, "r" );
        if( conf != NULL ) {
            while( getline( &line, &len, conf ) != -1) {
                pos = strchr( line, '=' );
                if( pos == NULL ) {
                    continue;
                }
                strncpy( name, line, pos - line );
                name[ pos - line ] = '\0';
                strncpy( val, pos + 1,
                         strlen( line ) - ((pos + 1) - line) - 1 );
                val[ strlen( line ) - ((pos + 1) - line) - 1 ] = '\0';
                if( !strcmp( "rpcport", name ) ) {
                    strcpy( rpcport, val );
                } else if ( !strcmp( "rpcconnect", name ) ) {
                    strcpy( rpcconnect, val );
                } else if ( !strcmp( "rpcuser", name ) ) {
                    strcpy( rpcuser, val );
                } else if ( !strcmp( "rpcpassword", name ) ) {
                    strcpy( rpcpass, val );
                }
            }
        }
        if( !strlen( rpcuser )) {
            sprintf( rpc_server, "%s%s:%s",
                     rpc_scheme, rpcconnect, rpcport );
        } else if( !strlen( rpcpass )) {
            sprintf( rpc_server, "%s%s@%s:%s",
                     rpc_scheme,
                     rpcuser,
                     rpcconnect, rpcport );
        } else {
            sprintf( rpc_server, "%s%s:%s@%s:%s",
                     rpc_scheme,
                     rpcuser, rpcpass,
                     rpcconnect, rpcport );
        }
        
        init = 1;
        
    }

    /* make rpc request */

    block_name = url + 4;
    headers = curl_slist_append( headers, "Content-Type: text/plain" );
    post_data = malloc( rpc_fmt_len + strlen( block_name ));
    bdgr_check( post_data == NULL, bdgr_malloc_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_scheme_nmc_free;
    }
    sprintf( post_data, rpc_fmt, block_name );
    
    /* initialize response data buffer */
    buf.data = NULL;
    curl_easy_setopt( handle, CURLOPT_URL, rpc_server );
    curl_easy_setopt( handle, CURLOPT_HTTPHEADER, headers );
    curl_easy_setopt( handle, CURLOPT_POSTFIELDS, post_data );
    curl_easy_setopt( handle, CURLOPT_WRITEFUNCTION, bdgr_record_data );
    curl_easy_setopt( handle, CURLOPT_WRITEDATA, &buf );
    curl_easy_perform( handle );

    bdgr_check( buf.error != bdgr_no_err, buf.error, __LINE__ );
    if( bdgr_error() ) {
        return bdgr_error();
    }
    buf.data = realloc( buf.data, buf.size + 1 );
    bdgr_check( buf.data == NULL, bdgr_realloc_err, __LINE__ );
    if( bdgr_error() ) {
        return bdgr_error();
    }
    buf.data[ buf.size++ ] = '\0';
    
    root = json_loads( buf.data, 0, bdgr_json_error() );
    bdgr_check( root == NULL,
                bdgr_json_load_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_scheme_nmc_free;
    }
    
    result = json_object_get( root, "result" );
    bdgr_check( result == NULL,
                bdgr_json_result_missing_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_scheme_nmc_free;
    }
    
    if( json_is_null( result )) {

        /* Error with RPC call */
        error = json_object_get( root, "error" );
        bdgr_check( error == NULL,
                    bdgr_json_error_missing_err, __LINE__ );
        if( bdgr_error() ) {
            goto bdgr_scheme_nmc_free;
        }

        bdgr_check( !json_is_object( error ),
                    bdgr_json_error_not_object_err, __LINE__ );
        if( bdgr_error() ) {
            goto bdgr_scheme_nmc_free;
        }

        message = json_object_get( error, "message" );
        bdgr_check( message == NULL,
                    bdgr_json_error_message_missing_err, __LINE__ );
        if( bdgr_error() ) {
            goto bdgr_scheme_nmc_free;
        }

        bdgr_check( !json_is_string( message ),
                    bdgr_json_error_message_not_string_err, __LINE__ );
        if( bdgr_error() ) {
            goto bdgr_scheme_nmc_free;
        }

        rpc_error = json_string_value( message );
        bdgr_check( rpc_error == NULL,
                    bdgr_json_error_message_err, __LINE__ );
        if( bdgr_error() ) {
            goto bdgr_scheme_nmc_free;
        }
        
        bdgr_rpc_error( rpc_error, __LINE__ );
        goto bdgr_scheme_nmc_free;
        
    }
    
    bdgr_check( !json_is_object( result ),
                bdgr_json_result_not_object_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_scheme_nmc_free;
    }
    
    value = json_object_get( result, "value" );
    bdgr_check( value == NULL,
                bdgr_json_value_missing_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_scheme_nmc_free;
    }

    bdgr_check( !json_is_string( value ),
                bdgr_json_value_not_string_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_scheme_nmc_free;
    }

    *record = json_string_value( value );
    bdgr_check( *record == NULL,
                bdgr_json_value_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_scheme_nmc_free;
    }
    

 bdgr_scheme_nmc_free:

    if( headers != NULL ) {
        curl_slist_free_all( headers );
    }
    if( post_data != NULL ) {
        free( post_data );
    }
    if( root != NULL ) {
        json_decref( root );
    }
    if( buf.data != NULL ) {
        free( buf.data );
    }

    curl_easy_cleanup( handle );

    return bdgr_error();

}

static int bdgr_scheme_id( const char* const url, const char** record )
{
    char* const nmc_url = malloc( strlen( url ) + 8 );
    bdgr_check( nmc_url == NULL, bdgr_malloc_err, __LINE__ );
    if( bdgr_error() ) {
        goto bdgr_scheme_id_free;
    }
    sprintf( nmc_url, "nmc:id/%s", strchr( url, ':' ) + 1 );
    bdgr_scheme_nmc( nmc_url, record );

 bdgr_scheme_id_free:
    
    free( nmc_url );
    return bdgr_error();
}

static int bdgr_scheme_http( const char* const url, const char** record )
{
    CURL* const handle = curl_easy_init();
    bdgr_buffer buf;
    buf.data = NULL;
    bdgr_check( buf.data == NULL, bdgr_malloc_err, __LINE__ );
    if( bdgr_error() ) {
        return bdgr_error();
    }
    curl_easy_setopt( handle, CURLOPT_URL, url );
    curl_easy_setopt( handle, CURLOPT_WRITEFUNCTION, bdgr_record_data );
    curl_easy_setopt( handle, CURLOPT_WRITEDATA, &buf );
    curl_easy_perform( handle );
    curl_easy_cleanup( handle );
    
    bdgr_check( buf.error != bdgr_no_err, buf.error, __LINE__ );
    if( bdgr_error() ) {
        return bdgr_error();
    }
    buf.data = realloc( buf.data, buf.size + 1 );
    bdgr_check( buf.data == NULL, bdgr_realloc_err, __LINE__ );
    if( bdgr_error() ) {
        return bdgr_error();
    }
    buf.data[ buf.size++ ] = '\0';
    
    *record = buf.data;
    return bdgr_no_err;
}

int bdgr_scheme_handler_add(
    char* scheme,
    int (*handle_url)( const char* const url, const char** record )
)
{
    struct bdgr_scheme_handler* handler =
        malloc( sizeof( struct bdgr_scheme_handler ));
    bdgr_check( handler == NULL, bdgr_malloc_err, __LINE__ );
    if( bdgr_error() ) {
        return bdgr_error();
    }
    handler->scheme = scheme;
    handler->handle_url = handle_url;
    handler->next = NULL;
    if( bdgr_scheme_handlers == NULL ) {
        bdgr_scheme_handlers = handler;
    } else {
        struct bdgr_scheme_handler* curr = bdgr_scheme_handlers;
        while( curr->next != NULL ) {
            curr = curr->next;
        }
        curr->next = handler;
    }
    return bdgr_no_err;
}

extern ltc_math_descriptor gmp_desc;

static int bdgr_init()
{
    static int init = 0;
    if( !init ) {
        
        ltc_mp = gmp_desc;

        bdgr_scheme_handler_add( "id:", bdgr_scheme_id );
        if( bdgr_error() ) {
            return bdgr_error();
        }
        
        bdgr_scheme_handler_add( "nmc:", bdgr_scheme_nmc );
        if( bdgr_error() ) {
            return bdgr_error();
        }
        
        bdgr_scheme_handler_add( "http:", bdgr_scheme_http );
        if( bdgr_error() ) {
            return bdgr_error();
        }
        
        bdgr_scheme_handler_add( "https:", bdgr_scheme_http );
        if( bdgr_error() ) {
            return bdgr_error();
        }
        
        init = 1;
        
    }
    return bdgr_no_err;
}
