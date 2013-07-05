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

/**
 * \todo { Implement decent error codes }
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

static void bdgr_init();

int bdgr_key_generate(
    const char* const password,
    bdgr_key* const key
)
{
    int err;
    prng_state prng;
    char sane_pass[64];
    int pass_len = strlen( password );

    bdgr_init();

    /* Create an rng we can seed with Alice's password */
    if ( register_prng( &rc4_desc ) == -1 ) {
        err = 1;
        goto bdgr_key_generate_free;
    }

    /* Start it */
    err = rc4_start( &prng );
    if ( err != CRYPT_OK) {
        goto bdgr_key_generate_free;
    }

    /* Sanity check */
    if( pass_len > 64 ) {
        goto bdgr_key_generate_free;
    }

    /* Copy the pass to a properly sized space */
    memcpy( sane_pass, password, pass_len );
    memset( sane_pass + pass_len, 0, sizeof( sane_pass ) - pass_len );

    /* Make sure the prng buffer starts fresh */
    memset( prng.rc4.buf, 0, 256 );

    /* Seed with Alice's password */
    err = rc4_add_entropy(
        (unsigned char*)sane_pass,
        sizeof( sane_pass ),
        &prng );
    if ( err != CRYPT_OK ) {
        goto bdgr_key_generate_free;
    }
    
    /* Ready and read */
    err = rc4_ready( &prng );
    if ( err != CRYPT_OK ) {
        goto bdgr_key_generate_free;
    }

    key->_impl = malloc( sizeof( dsa_key ));
    err = dsa_make_key(
        &prng, find_prng( "rc4" ),
        20, 128,
        (dsa_key*)key->_impl );
    if ( err != CRYPT_OK ) {
        goto bdgr_key_generate_free;
    }
    
 bdgr_key_generate_free:
    
    /* Scrub any copies of the password from memory */
    memset( prng.rc4.buf, 0, 256 );
    memset( sane_pass, 0, sizeof( sane_pass ));
    
    rc4_done( &prng );

    return err;
    
}

int bdgr_key_import(
    const unsigned char* const data,
    const unsigned long int data_len,
    bdgr_key* const key
)
{
    int err;
    bdgr_init();

    key->_impl = malloc( sizeof( dsa_key ));
    err = dsa_import( data, data_len, (dsa_key*)key->_impl );
    if( err ) {
        return err;
    }
    return 0;
}

int bdgr_key_decode(
    const char* const string,
    bdgr_key* const key
)
{
    int err;
    unsigned long int string_len = strlen( string );
    unsigned long int data_len = string_len;
    unsigned char* data = malloc( data_len );
    bdgr_init();
    
    err = base64_decode(
        (unsigned char*)string, string_len,
        data, &data_len );
    if( err ) {
        goto bdgr_key_decode_free;
    }
    
    err = bdgr_key_import( data, data_len, key );
    if( err ) {
        goto bdgr_key_decode_free;
    }

 bdgr_key_decode_free:

    free( data );
    return err;
}

int bdgr_key_export_public(
    const bdgr_key* const key,
    unsigned char* const data,
    unsigned long int* const data_len
)
{
    return dsa_export( data, data_len, PK_PUBLIC, (dsa_key*)key->_impl );
}

int bdgr_key_export_private(
    const bdgr_key* const key,
    unsigned char* const data,
    unsigned long int* const data_len
)
{
    return dsa_export( data, data_len, PK_PRIVATE, (dsa_key*)key->_impl );
}

static int bdgr_key_encode(
    const bdgr_key* const key,
    char** string,
    int type
)
{
    int err;
    char* string_out;
    unsigned long int data_len = 2048, string_out_len;
    unsigned char* data = malloc( data_len );
    if( type ) {
        err = bdgr_key_export_private( key, data, &data_len );
    } else {
        err = bdgr_key_export_public( key, data, &data_len );
    }
    if( err ) {
        goto bdgr_key_encode_free;
    }
    string_out_len = (data_len * 1.37) + 815;
    string_out = malloc( string_out_len );
    err = base64_encode(
        data, data_len,
        (unsigned char*)string_out, &string_out_len );
    if( err ) {
        goto bdgr_key_encode_free;
    }
    
 bdgr_key_encode_free:

    free( data );
    if( err ) {
        if( string_out ) {
            free( string_out );
        }
    } else {
        if( string_out ) {
            *string = string_out;
        }
    }
    return err;
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
}

int bdgr_token_sign(
    const unsigned char* const token,
    const unsigned long int token_len,
    const bdgr_key* const key,
    unsigned char* const signature,
    unsigned long int* const signature_len
)
{
    int err;
    prng_state prng;
    bdgr_init();
    
    if( register_prng( &fortuna_desc) == -1 ) {
        return 1;
    }
    err = rng_make_prng( 128, find_prng("fortuna"), &prng, NULL );
    if( err != CRYPT_OK) {
        return err;
    }
    return dsa_sign_hash(
        token, token_len,
        signature, signature_len,
        &prng, find_prng( "fortuna" ),
        (dsa_key*)key->_impl );
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
    badge->id = malloc( id_len );
    strcpy( badge->id, id );
    badge->token = malloc( token_len );
    memcpy( badge->token, token, token_len );
    badge->token_len = token_len;
    badge->signature = malloc( signature_len );
    memcpy( badge->signature, signature, signature_len );
    badge->signature_len = signature_len;
    return 0;
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
    return dsa_verify_hash(
        signature,
        signature_len,
        token,
        token_len,
        verified,
        (dsa_key*)key->_impl );
}

int bdgr_record_import(
    const char* const record,
    bdgr_key* const key
)
{
    int err;
    json_t* root, * dsa;
    json_error_t error;
    
    root = json_loads( record, 0, &error );
    if( !root ) {
        return 2;
    }

    dsa = json_object_get( root, "dsa" );
    if( !json_is_string( dsa )) {
        return 3;
    }

    err = bdgr_key_decode( json_string_value( dsa ), key );
    if( err ) {
        return 4;
    }
    
    json_decref( root );

    return err;

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
    int err;
    int support_scheme;
    bdgr_key key;
    struct bdgr_scheme_handler* curr;
    const char* record;

    bdgr_init();
    curr = bdgr_scheme_handlers;
    
    while( curr ) {
        if( !strncmp( badge->id, curr->scheme,
                      strlen( curr->scheme ))) {
            support_scheme = 1;
            err = curr->handle_url( badge->id, &record );
            if( err ) {
                return err;
            }
            break;
        }
        curr = curr->next;
    }
    if( !support_scheme ) {
        return 1;
    }

    err = bdgr_record_import( record, &key );
    if( err ) {
        return err;
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
    int err;
    json_t* root, * id, * token, * signature;
    json_error_t error;
    char const* tokenc, * signaturec;
    unsigned char* tokenb = 0, * signatureb = 0;
    unsigned long int tokenb_len, signatureb_len;

    root = json_loads( json_string, 0, &error );
    if( !root ) {
        err = 1;
        /* fprintf( stderr, "error: on line %d: %s\n", error.line, error.text );*/
        goto bdgr_badge_import_free;
    }

    id = json_object_get( root, "id" );
    if( !json_is_string( id )) {
        err = 2;
        goto bdgr_badge_import_free;
    }
    
    token = json_object_get( root, "token" );
    if( !json_is_string( token )) {
        err = 3;
        goto bdgr_badge_import_free;
    }
    
    signature = json_object_get( root, "signature" );
    if( !json_is_string( signature )) {
        err = 4;
        goto bdgr_badge_import_free;
    }

    tokenc = json_string_value( token );
    tokenb_len = strlen( tokenc );
    tokenb = malloc( tokenb_len );
    err = base64_decode(
        (unsigned char*)tokenc, tokenb_len,
        tokenb, &tokenb_len );
    if( err ){
        goto bdgr_badge_import_free;
    }
    
    signaturec = json_string_value( signature );
    signatureb_len = strlen( signaturec );
    signatureb = malloc( signatureb_len );
    err = base64_decode(
        (unsigned char*)signaturec, signatureb_len,
        signatureb, &signatureb_len );
    if( err ) {
        goto bdgr_badge_import_free;
    }

    err = bdgr_badge_make(
        json_string_value( id ),
        tokenb, tokenb_len,
        signatureb, signatureb_len,
        badge );
    if( err ) {
        goto bdgr_badge_import_free;
    }
    
 bdgr_badge_import_free:

    if( tokenb ) {
        free( tokenb );
    }
    if( signatureb ) {
        free( signatureb );
    }
    if( root ) {
        json_decref( root );
    }
    return err;
    
}

int bdgr_badge_export(
    const bdgr_badge* const badge,
    char** json_string
)
{
    int err;
    json_t* root;
    char* tokenc, * signaturec;
    unsigned long int tokenc_len, signaturec_len;
    
    tokenc_len = (badge->token_len * 1.37) + 815;
    tokenc = malloc( tokenc_len );
    
    signaturec_len = (badge->signature_len * 1.37) + 815;
    signaturec = malloc( signaturec_len );
    
    err = base64_encode(
        badge->token, badge->token_len,
        (unsigned char*)tokenc, &tokenc_len );
    if( err ) {
        goto bdgr_badge_export_free;
    }
    
    err = base64_encode(
        badge->signature, badge->signature_len,
        (unsigned char*)signaturec, &signaturec_len );
    if( err ) {
        goto bdgr_badge_export_free;
    }
    
    root = json_pack(
        "{ssssss}", /* Creeper object */
        "id", badge->id,
        "token", tokenc,
        "signature", signaturec );
    if( !root ) {
        err = 1;
        goto bdgr_badge_export_free;
    }

    *json_string = json_dumps( root, 0 );
    if( !*json_string ) {
        err = 2;
        goto bdgr_badge_export_free;
    }
    
 bdgr_badge_export_free:

    free( tokenc );
    free( signaturec );
    if( root ) {
        json_decref( root );
    }
    
    return err;
}

void bdgr_badge_free(
    bdgr_badge* const badge
)
{
    free( badge->id );
    free( badge->token );
    free( badge->signature );
}

typedef struct {
    char* data;
    unsigned long int size;
    unsigned long int pos;
    int overflow;
} bdgr_buffer;

static size_t bdgr_record_data(
    char *ptr,
    size_t size,
    size_t nmemb,
    void *_buf )
{
    bdgr_buffer *buf = (bdgr_buffer*)_buf;
    int sane_size = size*nmemb;
    if( buf->pos + sane_size > buf->size ) {
        buf->overflow += (buf->pos + sane_size) - buf->size;
        sane_size = buf->size - buf->pos;
    }
    memcpy( buf->data + buf->pos, ptr, sane_size );
    buf->pos += sane_size;
    return size;
}

static int bdgr_scheme_nmc( const char* const url, const char** record )
{
    int err;
    char* post_data, * response;
    const char* block_name;
    const char* const rpc_fmt =
        "{\"method\":\"name_show\",\"params\":[\"%s\"]}";
    const unsigned long int rpc_fmt_len = strlen( rpc_fmt ) - 2;
    struct curl_slist *headers = 0;
    bdgr_buffer buf;
    json_t* root, * result, * value;
    json_error_t error;
    CURL* const handle = curl_easy_init();
    static char* rpc_server = NULL;

    if( rpc_server == NULL ) {
        
        /* Parse out rpc connection details from bitcoin.conf */
        struct passwd* pw = getpwuid( getuid() );
        char* rel_path = "/.namecoin/bitcoin.conf";
        char* conf_path =
            malloc( strlen( pw->pw_dir ) + strlen( rel_path ) + 1);
        char name[80], val[256], * line = NULL, * pos;
        char* rpc_scheme = "http://";
        char* rpcport = "8336", * rpcconnect = "127.0.0.1";
        char* rpcuser = NULL, * rpcpass = NULL;
        size_t len;
        FILE* conf;
    
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
                    rpcport = malloc( strlen( val ) + 1 );
                    strcpy( rpcport, val );
                } else if ( !strcmp( "rpcconnect", name ) ) {
                    rpcconnect = malloc( strlen( val ) + 1 );
                    strcpy( rpcconnect, val );
                } else if ( !strcmp( "rpcuser", name ) ) {
                    rpcuser = malloc( strlen( val ) + 1 );
                    strcpy( rpcuser, val );
                } else if ( !strcmp( "rpcpassword", name ) ) {
                    rpcpass = malloc( strlen( val ) + 1 );
                    strcpy( rpcpass, val );
                }
            }
        }
        if( rpcuser == NULL ) {
            rpc_server = malloc( strlen( rpc_scheme ) +
                                 strlen( rpcconnect ) + 1
                                 + strlen( rpcport ) + 1 );
            sprintf( rpc_server, "%s%s:%s",
                     rpc_scheme, rpcconnect, rpcport );
        } else if( rpcpass == NULL ) {
            rpc_server = malloc(
                strlen( rpc_scheme ) + strlen( rpcuser ) + 1 +
                strlen( rpcconnect ) + 1 + strlen( rpcport ) + 1 );
            sprintf( rpc_server, "%s%s@%s:%s",
                     rpc_scheme,
                     rpcuser,
                     rpcconnect, rpcport );
        } else {
            rpc_server = malloc(
                strlen( rpc_scheme ) +
                strlen( rpcuser ) + 1 + strlen( rpcpass ) + 1 +
                strlen( rpcconnect ) + 1 + strlen( rpcport ) + 1 );
            sprintf( rpc_server, "%s%s:%s@%s:%s",
                     rpc_scheme,
                     rpcuser, rpcpass,
                     rpcconnect, rpcport );
        }
    }

    /* make rpc request */

    block_name = url + 4;
    headers = curl_slist_append( headers, "Content-Type: text/plain" );
    post_data = malloc( rpc_fmt_len + strlen( block_name ));
    sprintf( post_data, rpc_fmt, block_name );
    
    /* initialize response data buffer */
    buf.size = 2048;
    buf.data = malloc( buf.size );
    buf.pos = 0;
    buf.overflow = 0;

    curl_easy_setopt( handle, CURLOPT_URL, rpc_server );
    curl_easy_setopt( handle, CURLOPT_HTTPHEADER, headers );
    curl_easy_setopt( handle, CURLOPT_POSTFIELDS, post_data );
    curl_easy_setopt( handle, CURLOPT_WRITEFUNCTION, bdgr_record_data );
    curl_easy_setopt( handle, CURLOPT_WRITEDATA, &buf );
    curl_easy_perform( handle );

    response = malloc( buf.pos+1 );
    memcpy( response, buf.data, buf.pos );
    response[ buf.pos ] = '\0';

    /* decode json response */
    root = json_loads( response, 0, &error );
    if( !root ) {
        err = 1;
        goto bdgr_scheme_nmc_free;
    }

    result = json_object_get( root, "result" );
    if( json_is_null( result )) {
        err = 2;
        goto bdgr_scheme_nmc_free;
    }

    value = json_object_get( result, "value" );
    if( !json_is_string( value )) {
        err = 3;
        goto bdgr_scheme_nmc_free;
    }

    *record = json_string_value( value );

 bdgr_scheme_nmc_free:

    json_decref( root );
    free( buf.data );

    return err;

}

static int bdgr_scheme_id( const char* const url, const char** record )
{
    int err;
    char* const nmc_url = malloc( strlen( url ) + 8 );
    sprintf( nmc_url, "nmc:id/%s", strchr( url, ':' ) + 1 );
    err = bdgr_scheme_nmc( nmc_url, record );
    free( nmc_url );
    return err;
}

int bdgr_scheme_http( const char* const url, const char** record )
{
    CURL* const handle = curl_easy_init();
    bdgr_buffer buf;
    buf.size = 1024;
    buf.data = malloc( buf.size );
    buf.pos = 0;
    buf.overflow = 0;
    curl_easy_setopt( handle, CURLOPT_URL, url );
    curl_easy_setopt( handle, CURLOPT_WRITEFUNCTION, bdgr_record_data );
    curl_easy_setopt( handle, CURLOPT_WRITEDATA, &buf );
    curl_easy_perform( handle );
    buf.data[ buf.pos ] = '\0';
    *record = malloc( buf.size );
    return 0;
}

void bdgr_scheme_handler_add(
    char* scheme,
    int (*handle_url)( const char* const url, const char** record )
)
{
    struct bdgr_scheme_handler* handler =
        malloc( sizeof( struct bdgr_scheme_handler ));
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
}

extern ltc_math_descriptor gmp_desc;

static void bdgr_init()
{
    static int init = 0;
    if( !init ) {
        init = 1;
        ltc_mp = gmp_desc;
        bdgr_scheme_handler_add( "id:", bdgr_scheme_id );
        bdgr_scheme_handler_add( "nmc:", bdgr_scheme_nmc );
        bdgr_scheme_handler_add( "http:", bdgr_scheme_http );
        bdgr_scheme_handler_add( "https:", bdgr_scheme_http );
    }
}
