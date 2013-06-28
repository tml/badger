/* Copyright (c) 2013 John Driscoll */

#ifndef BADGER_H
#define BADGER_H

int bdgr_make_badge(
    unsigned char* badge,
    long unsigned int* badge_len,
    const unsigned char* token,
    const unsigned long int token_len,
    const unsigned char* name,
    const unsigned long int name_len,
    const unsigned char* pass,
    const unsigned long int pass_len );

int bdgr_verify_badge(
    const unsigned char* badge,
    const long unsigned int badge_len,
    unsigned char* name,
    unsigned long int* name_len,
    unsigned char* token,
    unsigned long int* token_len,
    int* verified );

#endif
