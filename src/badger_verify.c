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
        fprintf( stderr, "badge import error\n" );
        exit( err );
    }
    
    err = bdgr_badge_verify( &badge, &verified );
    if( err ) {
        fprintf( stderr, "error verifying badge\n" );
        exit( err );
    }

    if( verified ) {
        fprintf( stderr, "Verified" );
    } else {
        fprintf( stderr, "Not verified" );
        exit( 1 );
    }
    
    return 0;
    
}
