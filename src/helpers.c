/* helpers.c
*
* Copyright (C) 2013 wolfSSL Inc.
*
* This file is part of cert service 
*
* All rights reserved.
*
*/


#include "helpers.h"

/* convert short to network byte order, no alignment required */
void c16toa(unsigned short u16, unsigned char* c)
{
    c[0] = (u16 >> 8) & 0xff;
    c[1] =  u16 & 0xff;
}

/* convert opaque to 16 bit integer */
void ato16(const unsigned char* c, unsigned short* u16)
{
    *u16 = (c[0] << 8) | (c[1]);
}

