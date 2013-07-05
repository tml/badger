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
#include <unistd.h>
#include <getopt.h>
#include <jansson.h>
#include <badger.h>

void usage()
{
    fprintf(
        stderr,
        "Usage: badger_key\n"
        "Options:\n"
        "-p, --pass  <password>\n"
        "-k, --key   <base64-dsa-public-key>\n"
    );
}

int main( const int argc, char* const* argv )
{
    int err;
    json_t* root;
    char* pass = NULL, * key_string = NULL, * string = NULL;
    unsigned long int pass_len;
    bdgr_key key;
    int c;
    
    while (1) {
        static struct option long_options[] = {
            { "pass", required_argument, 0, 'p' },
            { "key",  required_argument, 0, 'k' },
            { 0, 0, 0, 0 }
        };
        int option_index = 0;
        c = getopt_long( argc, argv, "p:", long_options, &option_index);
        if (c == -1)
            break;
        switch(c) {
        case 'p':
            pass = optarg;
            pass_len = strlen( pass );
            break;
        case 'k':
            key_string = optarg;
            break;
        case '?':
            break;
        default:
            abort();
        }
    }

    if( key_string == NULL ) {
        
        if( pass == NULL && key_string == NULL ) {
            pass = getpass( "Enter password: " );
            pass_len = strlen( pass );
        }
        
        if( !pass_len ) {
            usage();
            exit( 1 );
        }
        
        err = bdgr_key_generate( pass, &key );
        if( err ) {
            fprintf( stderr,
                     "error generating key: %s\n",
                     bdgr_error_string( err ));
            exit( err );
        }
        
        err = bdgr_key_encode_public( &key, &key_string );
        if( err ) {
            fprintf( stderr,
                     "error encoding key: %s\n",
                     bdgr_error_string( err ));
            exit( err );
        }
        
    }

    root = json_pack(
        "{ss}",
        "dsa", key_string );
    if( root == NULL ) {
        fprintf( stderr, "error packing json\n" );
        exit( 1 );
    }

    string = json_dumps( root, 0 );
    if( !string ) {
        fprintf( stderr, "error dumping json\n" );
        exit( 2 );
    }
    
    puts( string );
    
    return 0;
    
}
