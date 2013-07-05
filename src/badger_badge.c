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
#include <stdio.h>
#include <tomcrypt.h>
#include <badger.h>

#define BUF_SIZE 1024

void usage()
{
    fprintf(
        stderr,
        "Usage: badger_badge <id> <base64-token>\n"
        "A record must be available from stdin.\n"
    );
}

int main( const int argc, char* const* argv )
{

    int err;
    bdgr_key key;
    bdgr_badge badge;
    char* key_string, * id, * token, * badge_string;
    unsigned long int token_len, tokenb_len, signature_len = 2048;
    unsigned char* tokenb, * signature = malloc( signature_len );
    char buffer[BUF_SIZE];
    size_t key_len = 1;

    if( argc != 3 ) {
        usage();
        exit( 1 );
    }
    
    key_string = malloc( BUF_SIZE );
    key_string[0] = '\0';
    while( fgets( buffer, BUF_SIZE, stdin )) {
        key_len += strlen( buffer );
        key_string = realloc( key_string, key_len );
        strcat( key_string, buffer );
    }
    err = bdgr_key_decode( key_string, &key );
    if( err ) {
        fprintf( stderr,
                 "error decoding key: %s\n",
                 bdgr_error_string( err ));
        exit( err );
    }
        
    id = argv[ 1 ];
    token = argv[ 2 ];
    token_len = strlen( token );

    tokenb_len = token_len;
    tokenb = malloc( tokenb_len );
    err = base64_decode( (unsigned char*)token, token_len, tokenb, &tokenb_len );
    if( err ) {
        fprintf( stderr,
                 "error decoding token: %s\n",
                 bdgr_error_string( err ));
        exit( err );
    }

    err = bdgr_token_sign( tokenb, tokenb_len, &key, signature, &signature_len );
    if( err ) {
        fprintf( stderr,
                 "error signing token: %s\n",
                 bdgr_error_string( err ));
        exit( err );
    }

    err = bdgr_badge_make( id, tokenb, tokenb_len, signature, signature_len, &badge );
    if( err ) {
        fprintf( stderr,
                 "error making badge: %s\n",
                 bdgr_error_string( err ));
        exit( err );
    }
    
    err = bdgr_badge_export( &badge, &badge_string );
    if( err ) {
        fprintf( stderr,
                 "error exporting badge: %s\n",
                 bdgr_error_string( err ));
        exit( err );
    }

    puts( badge_string );
    
    return 0;
    
}
