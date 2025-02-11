//$TAG BIZDEV
//  $IPCategory:     
//  $DealPointID:    41723
//  $AgreementName:  zlib license
//  $AgreementType:  oss license
//  $ExternalOrigin: mark adler;jean-loup gailly
//$ENDTAG

//$TAG ENGR 
//  $Owner:    bryant
//  $Module:   base_zlib
//
//$ENDTAG

/* inffast.h -- header to use inffast.c
 * Copyright (C) 1995-2002 Mark Adler
 * For conditions of distribution and use, see copyright notice in zlib.h 
 */

/* WARNING: this file should *not* be used by applications. It is
   part of the implementation of the compression library and is
   subject to change. Applications should only use zlib.h.
 */

extern int inflate_fast OF((
    uInt,
    uInt,
    inflate_huft *,
    inflate_huft *,
    inflate_blocks_statef *,
    z_streamp ));
