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

#ifndef BADGER_ERR_H
#define BADGER_ERR_H

#include <jansson.h>

typedef enum {
    bdgr_no_err,
    bdgr_malloc_err,
    bdgr_realloc_err,
    bdgr_crypt_err,
    bdgr_register_prng_err,
    bdgr_json_load_err,
    bdgr_json_pack_err,
    bdgr_json_dump_err,
    bdgr_json_dsa_missing_err,
    bdgr_json_dsa_not_string_err,
    bdgr_json_dsa_err,
    bdgr_json_id_missing_err,
    bdgr_json_id_not_string_err,
    bdgr_json_id_err,
    bdgr_json_token_missing_err,
    bdgr_json_token_not_string_err,
    bdgr_json_token_err,
    bdgr_json_signature_missing_err,
    bdgr_json_signature_not_string_err,
    bdgr_json_signature_err,
    bdgr_json_result_missing_err,
    bdgr_json_result_not_object_err,
    bdgr_json_result_err,
    bdgr_json_value_missing_err,
    bdgr_json_value_not_string_err,
    bdgr_json_value_err,
    bdgr_json_error_missing_err,
    bdgr_json_error_not_object_err,
    bdgr_json_error_message_missing_err,
    bdgr_json_error_message_not_string_err,
    bdgr_json_error_message_err,
    bdgr_rpc_err,
    bdgr_response_overflow,
    bdgr_password_len_err,
    bdgr_unsupported_scheme_err
} bdgr_err;

int bdgr_error();

int bdgr_check( int ret, bdgr_err err, int line );

int bdgr_crypt( int ret, int line );

json_error_t *bdgr_json_error();

void bdgr_rpc_error( const char* err, int line );

#endif
