#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <badger.h>

void usage()
{
    printf(
        "Usage: badger_key\n"
        "Options:\n"
        "-p, --pass  password\n"
    );
}

int main( const int argc, char* const* argv )
{
    int err;
    char* pass = NULL, * string = NULL;
    unsigned long int pass_len;
    bdgr_key key;
    int c;
    
    while (1) {
        static struct option long_options[] = {
            { "pass", required_argument, 0, 'p' },
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
        case '?':
            break;
        default:
            abort();
        }
    }

    if( pass == NULL ) {
        pass = getpass( "Enter password: " );
        pass_len = strlen( pass );
    }

    if( !pass_len ) {
        usage();
        exit( 1 );
    }

    err = bdgr_key_generate( pass, &key );
    if( err ) {
        fprintf( stderr, "error generating key\n" );
        exit( err );
    }

    err = bdgr_key_encode_private( &key, &string );
    if( err ) {
        fprintf( stderr, "error encoding key\n" );
        exit( err );
    }

    puts( string );
    
    return 0;
    
}
