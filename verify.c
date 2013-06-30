#include <badger.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main()
{
    
    /* Alice's input to client */
    unsigned char* name = (unsigned char*)"alice";
    unsigned long int name_len = strlen( (char*)name );
    unsigned char* pass = (unsigned char*)"secret";
    unsigned long int pass_len = strlen( (char*)pass );
    unsigned char badge[4096];
    unsigned long int badge_len = sizeof( badge );
    unsigned char token[32];
    unsigned long int token_len = sizeof( token );
    unsigned char name_out[32];
    unsigned long int name_out_len = 32;
    unsigned char token_out[2048];
    unsigned long int token_out_len = 2048;
    int verified;
    int err;

    memset( token, 'a', sizeof( token ));

    err = bdgr_make_badge(
        badge, &badge_len,
        token, token_len,
        name, name_len,
        pass, pass_len );
    if( err ) {
        printf("Error making badge: %d\n", err);
        return err;
    }

    err = bdgr_verify_badge(
        badge, badge_len,
        name_out, &name_out_len,
        token_out, &token_out_len,
        &verified );
    if( err ) {
        printf("Error verifying badge\n");
        return err;
    }

    if( verified ) {
        printf("Badge is good!\n");
    } else {
        printf("Badge is not good!\n");
    }

    return 0;
    
}
