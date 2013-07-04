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

#ifndef BADGER_H
#define BADGER_H

/*!
   \struct bdgr_badge
   \brief The badge data structure.
   \note Use bdgr_badge_free() to release resources.
*/
struct bdgr_badge {
    
    /*!
       \var bdgr_badge::id
       A null-terminated Identity URL.
    */
    char*             id;

    /*!
       \var bdgr_badge::token
       Raw token data.
    */
    unsigned char*    token;

    /*!
       \var bdgr_badge::token_len
       The size in bytes of bdgr_badge::token
    */
    unsigned long int token_len;

    /*!
       \var bdgr_badge::signature
       Raw signature data.
    */
    unsigned char*    signature;

    /*!
       \var bdgr_badge::signature_len
       The size in bytes of bdgr_badge::signature
    */
    unsigned long int signature_len;
    
};
typedef struct bdgr_badge bdgr_badge;

/*!
  \struct bdgr_key
  \brief
  The badger key container.  A wrapper for libtomcrypt dsa_key.
  \note
  Use bdgr_key_free() to release resources.
 */
struct bdgr_key {
    void* _impl;
};
typedef struct bdgr_key bdgr_key;

/*!
  Initializes \c key using \c password as entropy.
  \param[in]  password  Null-terminated user-supplied password.
  \param[out] key       Key to initialize.
 */
int bdgr_key_generate(
    const char* password,
    bdgr_key* key
);

/*!
  Initializes key using raw DSA key data of length data_len in libtomcrypt's
  DSA key format.
  \param[in]  data      Raw DSA key data.
  \param[in]  data_len  Length of \c data.
  \param[out] key       Key to initialize.
*/
int bdgr_key_import(
    const unsigned char* data,
    const unsigned long int data_len,
    bdgr_key* key
);

/*!
  Initializes key from base64 encoded character data. Key data must be in
  libtomcrypt DSA key format.
  \param[in]  data  Raw DSA key data.
  \param[out] key   Key to initialize.
*/
int bdgr_key_decode(
    const char* data,
    bdgr_key* key
);

/*
  Export public key to raw DSA key format and places it in data of initial
  length data_len.
*/
int bdgr_key_export_public(
    const bdgr_key* const key,
    unsigned char* const data,
    unsigned long int* const data_len
);

/*
  Export private key to raw DSA key format and places it in data of initial
  length data_len.
*/
int bdgr_key_export_private(
    const bdgr_key* key,
    unsigned char* data,
    unsigned long int* data_len
);

/*
  Export public key to base64 encoded character data. String must be freed by
  user with free().
*/
int bdgr_key_encode_public(
    const bdgr_key* key,
    char** string
);

/*
  Export private key to base64 encoded character data. String must be freed by
  user with free().
*/
int bdgr_key_encode_private(
    const bdgr_key* key,
    char** string
);

/*
  Releases resources owned by key.
*/
void bdgr_key_free(
    bdgr_key* key
);

/*
  Signs a token using a private DSA key.  The signature is written to signature
  of initial length signature_len.
*/
int bdgr_token_sign(
    const unsigned char* token,
    const unsigned long int token_len,
    const bdgr_key* key,
    unsigned char* signature,
    unsigned long int* signature_len
);

/*
  Copies all data into a badge struct. Use bdgr_badge_free to release resources.
*/
int bdgr_badge_make(
    const char* id,
    const unsigned char* token,
    const unsigned long int token_len,
    const unsigned char* signature,
    const unsigned long signature_len,
    bdgr_badge* badge
);

/*
  Verify a badge. The verified flag will be set accordingly.
*/
int bdgr_badge_verify(
    const bdgr_badge* badge,
    int* verified
);

/*!
  Verify a token was signed by a public DSA key.
*/
int bdgr_signature_verify(
    const unsigned char* token,
    const unsigned long int token_len,
    const unsigned char* signature,
    const unsigned long int signature_len,
    const bdgr_key* key,
    int* verified
);

/*!
  Parses out the DSA public \c key in \c record.
  @param[in]   record  JSON-encoded record containing "dsa" attribute.
  @param[out]  key     DSA key container.
*/
int bdgr_record_import(
    const char* record,
    bdgr_key* key
);

/*!
  Import a badge from JSON.
*/
int bdgr_badge_import(
    const char* json_string,
    bdgr_badge* badge
);

/*!
  Export a badge to JSON. You must call free() on \c json_string when done.
*/
int bdgr_badge_export(
    const bdgr_badge* badge,
    char** json_string
);

/*
  Free resources owned by badge.
*/
void bdgr_badge_free(
    bdgr_badge* badge
);

/*!
  Add a scheme handler to bdgr_badge_verify().
*/
void bdgr_scheme_handler_add(
    char* scheme,
    int (*handle_url)( const char* url, const char** record )
);

#endif
