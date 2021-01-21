/* visibility.h
*
* Copyright (C) 2021 wolfSSL Inc.
*
* This file is part of wolf key manager
*
* All rights reserved.
*
*/


/* Visibility control macros */

#ifndef WOLFKM_VISIBILITY_H
#define WOLFKM_VISIBILITY_H


/* WOLFKM_API is used for the public API symbols.
        It either imports or exports (or does nothing for static builds)

   WOLFKM_LOCAL is used for non-API symbols (private).
*/

#if defined(BUILDING_WKM)
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__)
        #if defined(WOLFKM_DLL)
            #define WOLFKM_API __declspec(dllexport)
        #else
            #define WOLFKM_API
        #endif
        #define WOLFKM_LOCAL
    #elif defined(HAVE_VISIBILITY) && HAVE_VISIBILITY
        #define WOLFKM_API   __attribute__ ((visibility("default")))
        #define WOLFKM_LOCAL __attribute__ ((visibility("hidden")))
    #elif defined(__SUNPRO_C) && (__SUNPRO_C >= 0x550)
        #define WOLFKM_API   __global
        #define WOLFKM_LOCAL __hidden
    #else
        #define WOLFKM_API
        #define WOLFKM_LOCAL
    #endif /* HAVE_VISIBILITY */
#else /* BUILDING_WKM */
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__)
        #if defined(WOLFKM_DLL)
            #define WOLFKM_API __declspec(dllimport)
        #else
            #define WOLFKM_API
        #endif
        #define WOLFKM_LOCAL
    #else
        #define WOLFKM_API
        #define WOLFKM_LOCAL
    #endif
#endif /* BUILDING_WOLFKM */


#endif /* WOLFKM_VISIBILITY_H */
