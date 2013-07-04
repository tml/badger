#include <stdlib.h>
#include <stdio.h>
#include <badger.h>

void usage()
{
    printf(
        "Usage: badger_verify <badge-string>\n"
    );
}

int main( const int argc, char* const* argv )
{

    int err;
    bdgr_badge badge;
    int verified;

    if( argc != 2 ) {
        usage();
        exit( 1 );
    }

    err = bdgr_badge_import( argv[1], &badge );
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
