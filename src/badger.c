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

/*
  TODO: Implement decent error codes
*/

#include <badger.h>
#include <tomcrypt.h>
#include <jansson.h>

extern ltc_math_descriptor gmp_desc;

static void bdgr_init()
{
    ltc_mp = gmp_desc;
}

int bdgr_key_generate(
    const char* const password,
    bdgr_key* const key
)
{
    int err;
    prng_state prng;
    char* sane_pass;
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
    sane_pass = malloc( 64 );
    memcpy( sane_pass, password, pass_len );
    memset( sane_pass + pass_len, 0, 64 - pass_len );

    /* Make sure the prng buffer starts fresh */
    memset( prng.rc4.buf, 0, 256 );

    /* Seed with Alice's password */
    err = rc4_add_entropy( (unsigned char*)sane_pass, 64, &prng );
    if ( err != CRYPT_OK ) {
        goto bdgr_key_generate_free;
    }
    
    /* Ready and read */
    err = rc4_ready( &prng );
    if ( err != CRYPT_OK ) {
        goto bdgr_key_generate_free;
    }

    err = dsa_make_key(
        &prng, find_prng( "rc4" ),
        30, 256,
        (dsa_key*)key->_impl );
    if ( err != CRYPT_OK ) {
        goto bdgr_key_generate_free;
    }
    
 bdgr_key_generate_free:
    
    /* Scrub any copies of the password from memory */
    memset( prng.rc4.buf, 0, 256 );
    
    rc4_done( &prng );
    if( sane_pass ) {
        memset( sane_pass, 0, 64 );
        free( sane_pass );
    }
    
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
    unsigned long int data_len = (string_len * 1.37) + 815;
    unsigned char* data = malloc( data_len );
    
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
    memcpy( badge->id, id, id_len );
    badge->token = malloc( token_len );
    memcpy( badge->token, token, token_len );
    badge->token_len = token_len;
    badge->signature = malloc( signature_len );
    memcpy( badge->signature, signature, signature_len );
    badge->signature_len = signature_len;
    return 0;
}

int bdgr_badge_verify(
    const bdgr_badge* const badge,
    const bdgr_key* const key,
    int* const verified
)
{
    bdgr_init();
    return dsa_verify_hash(
        badge->signature,
        badge->signature_len,
        badge->token,
        badge->token_len,
        verified,
        (dsa_key*)key->_impl );
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
        /* fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);*/
        goto bdgr_badge_import_free;
    }

    id = json_object_get( root, "id" );
    if( !json_is_string( id )) {
        goto bdgr_badge_import_free;
    }
    
    token = json_object_get( root, "token" );
    if( !json_is_string( token )) {
        goto bdgr_badge_import_free;
    }
    
    signature = json_object_get( root, "signature" );
    if( !json_is_string( signature )) {
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
    char* json_string
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
        "{sssss}", /* Creeper object */
        "id", badge->id,
        "token", tokenc,
        "signature", signaturec );
    if( !root ) {
        err = 1;
        goto bdgr_badge_export_free;
    }

    json_string = json_dumps( root, 0 );
    if( !json_string ) {
        err = 1;
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
