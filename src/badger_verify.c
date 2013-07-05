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
#include <stdio.h>
#include <string.h>
#include <badger.h>

#define BUF_SIZE 1024

void usage()
{
    fprintf(
        stderr,
        "Usage: badger_verify <badge-string>\n"
    );
}

int main( const int argc, char* const* argv )
{

    int err;
    char* badge_string;
    bdgr_badge badge;
    int verified;

    if( argc == 2 ) {
        badge_string = argv[1];
    } else {
        char buffer[BUF_SIZE];
        size_t badge_len = 1;
        badge_string = malloc( BUF_SIZE );
        badge_string[0] = '\0';
        while( fgets( buffer, BUF_SIZE, stdin )) {
            badge_len += strlen( buffer );
            badge_string = realloc( badge_string, badge_len );
            strcat( badge_string, buffer );
        }
    }

    err = bdgr_badge_import( badge_string, &badge );
    if( err ) {
        fprintf( stderr,
                 "badge import error: %s\n",
                 bdgr_error_string( err ));
        exit( err );
    }

    err = bdgr_badge_verify( &badge, &verified );
    if( err ) {
        fprintf( stderr,
                 "error verifying badge: %s\n",
                 bdgr_error_string( err ));
        exit( err );
    }

    if( verified ) {
        puts( "Signature verified" );
    } else {
        puts( "Signature does not match id" );
        exit( 1 );
    }
    
    return 0;
    
}
