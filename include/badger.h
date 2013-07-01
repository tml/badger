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

/*
  The badge data structure.  Use bdgr_badge_free to release resources.
 */
typedef struct {
    char*             id;
    unsigned char*    token;
    unsigned long int token_len;
    unsigned char*    signature;
    unsigned long int signature_len;
} bdgr_badge;

/*
  The badger key container.  A wrapper for libtomcrypt dsa_key.
  Use bdgr_key_free to release resources.
 */
typedef struct {
    void* _impl;
} bdgr_key;

/*
  Creates a key using password as entropy.
*/
int bdgr_key_generate(
    const char* const password,
    bdgr_key* const key
);

/*
  Import binary key data.  Key data must be in libtomcrypt DSA key format.
*/
int bdgr_key_import(
    const unsigned char* const data,
    const unsigned long int data_len,
    bdgr_key* const key
);

/*
  Import key from base64 encoded character data. Key data must be in libtomcrypt
  DSA key format.
*/
int bdgr_key_decode(
    const char* const data,
    bdgr_key* const key
);

/*
  Releases resources owned by key.
*/
void bdgr_key_free(
    bdgr_key* const key
);

/*
  Signs a token using a private DSA key.
*/
int bdgr_token_sign(
    const unsigned char* const token,
    const unsigned long int token_len,
    const bdgr_key* const key,
    unsigned char* const signature,
    unsigned long int* const signature_len
);

/*
  Copies all data into a badge struct. Use bdgr_badge_free to release resources.
*/
int bdgr_badge_make(
    const char* const id,
    const unsigned char* const token,
    const unsigned long int token_len,
    const unsigned char* const signature,
    const unsigned long int signature_len,
    bdgr_badge* const badge
);

/*
  Verify a badge came from public DSA key.
*/
int bdgr_badge_verify(
    const bdgr_badge* const badge,
    const bdgr_key* const key,
    int* const verified
);

/*
  Import a badge from JSON.
*/
int bdgr_badge_import(
    const char* const json_string,
    bdgr_badge* const badge
);

/*
  Export a badge to JSON.
*/
int bdgr_badge_export(
    const bdgr_badge* const badge,
    char* json_string
);

/*
  Free resources owned by badge.
*/
void bdgr_badge_free(
    bdgr_badge* const badge
);

#endif
