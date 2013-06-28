/* Copyright (c) 2013 John Driscoll */

#include <badger.h>
#include <tomcrypt.h>

extern ltc_math_descriptor gmp_desc;

/* Badge owner structure */
typedef struct
{
    prng_state prng;
    unsigned char* pass;
    
} bdgr_id_owner;

/* Will be removed */
extern unsigned long int test_key_len;
extern unsigned char test_key[822];

/* Init a badge owner context */
static int bdgr_open_id_owner( bdgr_id_owner* owner, const unsigned char* pass, const unsigned long int pass_len )
{
    int err;

    /* Use gmp math library */
    ltc_mp = gmp_desc;

    /* Copy the pass to a properly sized space */
    owner->pass = malloc( 64 );
    strncpy( (char*)owner->pass, (char*)pass, pass_len );
    memset( (char*)owner->pass + pass_len, 0, 64 - pass_len );
    
    /* Create an rng we can seed with Alice's password */
    if ( register_prng( &rc4_desc ) == -1 ) {
        return 1;
    }

    /* Start it */
    err = rc4_start( &owner->prng );
    if ( err != CRYPT_OK) {
        return err;
    }

    /* Make sure the prng buffer starts fresh */
    memset( owner->prng.rc4.buf, 0, 256 );

    /* Seed with Alice's password */
    err = rc4_add_entropy( owner->pass, 64, &owner->prng );
    if ( err != CRYPT_OK ) {
        return err;
    }
    
    /* Ready and read */
    err = rc4_ready( &owner->prng );
    if ( err != CRYPT_OK ) {
        return err;
    }

    return 0;
    
}

/* Free memory associated with owner id */
static void bdgr_close_id_owner( bdgr_id_owner* owner )
{
    rc4_done( &owner->prng );
    free( owner->pass );
}

/* Generate the private key for a badge owner */
static int bdgr_private_dsa_key( dsa_key* key, bdgr_id_owner* owner )
{
    int err;
    err = dsa_make_key( &owner->prng, find_prng( "rc4" ), 30, 256, key );
    if ( err != CRYPT_OK ) {
        return err;
    }
    return 0;
}

/* Retrieve the public key for a name */
static int bdgr_public_dsa_key( dsa_key* key, const unsigned char* name, const unsigned long int name_len )
{
    int err = dsa_import( test_key, test_key_len, key );
    if( err ) {
        return err;
    }
    return 0;
}

/* Construct a badge with given token and name */
int bdgr_make_badge(
    unsigned char* badge,
    unsigned long int* badge_len,
    const unsigned char* token,
    const unsigned long int token_len,
    const unsigned char* name,
    const unsigned long int name_len,
    const unsigned char* pass,
    const unsigned long int pass_len )
{
    
    int err;
    bdgr_id_owner owner;
    dsa_key key;
    unsigned long int token_hash_len = 2048;
    unsigned char token_hash[ 2048 ];
    unsigned long int head_len = name_len + token_len + 2;
    unsigned long int string_len = *badge_len - head_len;

    /* Sanity check */
    if( *badge_len <= head_len ) {
        err = 1;
        goto bdgr_make_badge_free;
    }
    
    /* Create an owner context */
    err = bdgr_open_id_owner( &owner, pass, pass_len );
    if( err ) goto bdgr_make_badge_free;

    /* Create a signature */
    err = bdgr_private_dsa_key( &key, &owner );
    if( err ) goto bdgr_make_badge_free;

    /* Create a hash of the token */
    err = dsa_sign_hash( token, token_len, token_hash, &token_hash_len, &owner.prng, find_prng( "rc4" ), &key );
    if( err != CRYPT_OK ) goto bdgr_make_badge_free;

    /* Write the name */
    memcpy( badge, name, name_len );
    badge[ name_len ] = '\n';

    /* Write the plaintext token */
    memcpy( badge + name_len + 1, token, token_len );
    badge[ name_len + 1 + token_len ] = '\n';

    /* Write an printable string of the hash */
    err = base64_encode( token_hash, token_hash_len, badge + head_len,  &string_len );
    if( err != CRYPT_OK ) goto bdgr_make_badge_free;

    *badge_len = head_len + string_len;
    
 bdgr_make_badge_free:
    
    bdgr_close_id_owner( &owner );
    return err;
}

/* Verify a badge and store the name and token it contains. This has no concept of token validity. */
int bdgr_verify_badge(
    const unsigned char* badge,
    const unsigned long int badge_len,
    unsigned char* name,
    unsigned long int* name_len,
    unsigned char* token,
    unsigned long int* token_len,
    int* verified )
{
    int err;
    dsa_key key;
    unsigned long int token_hash_len = 2048;
    unsigned char token_hash[ 2048 ];
    unsigned long int token_hash_bin_len = 2048;
    unsigned char token_hash_bin[ 2048 ];
    unsigned char* badge_ptr = (unsigned char*)badge;
    unsigned char* name_ptr = name;
    unsigned char* token_ptr = token;
    unsigned char* token_hash_ptr = token_hash;
    
    /* Extract name */
    while( *badge_ptr != '\n' ) {
        if( badge_ptr == badge + badge_len ||
            *name_len == (unsigned long int)(name_ptr - name) ) {
            return 1;
        }
        *name_ptr++ = *badge_ptr++;
    }
    if( name_ptr == name ) {
        return 1;
    }
    *name_len = name_ptr - name;
    ++badge_ptr;

    /* Extract token */
    while( *badge_ptr != '\n' ) {
        if( badge_ptr == badge + badge_len ||
            *token_len == (unsigned long int)(token_ptr - token) ) {
            return 1;
        }
        *token_ptr++ = *badge_ptr++;
    }
    if( token_ptr == token ) {
        return 1;
    }
    *token_len = token_ptr - token;
    ++badge_ptr;

    /* Extract token hash */
    while( badge_ptr != badge + badge_len ) {
        *token_hash_ptr++ = *badge_ptr++;
    }
    if( token_hash_ptr == token_hash ) {
        return 1;
    }
    token_hash_len = token_hash_ptr - token_hash;
    
    /* Decode token hash from base64 */
    err = base64_decode( token_hash, token_hash_len, token_hash_bin,  &token_hash_bin_len );
    
    /* Get the public key */
    err = bdgr_public_dsa_key( &key, name, *name_len );
    if( err ) {
        return err;
    }
    
    /* Verify */
    return dsa_verify_hash( token_hash_bin, token_hash_bin_len, token, *token_len, verified, &key );

}
