// libpng_read_fuzzer.cc
// Copyright 2017-2018 Glenn Randers-Pehrson
// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that may
// be found in the LICENSE file https://cs.chromium.org/chromium/src/LICENSE

// The modifications in 2017 by Glenn Randers-Pehrson include
// 1. addition of a PNG_CLEANUP macro,
// 2. setting the option to ignore ADLER32 checksums,
// 3. adding "#include <string.h>" which is needed on some platforms
//    to provide memcpy().
// 4. adding read_end_info() and creating an end_info structure.
// 5. adding calls to png_set_*() transforms commonly used by browsers.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#define PNG_INTERNAL
#include "png.h"




static png_alloc_size_t allocated_mem = 0;

void* limited_malloc(png_alloc_size_t size) {
  // libpng may allocate large amounts of memory that the fuzzer reports as
  // an error. In order to silence these errors, make libpng fail when trying
  // to allocate a large amount. This allocator used to be in the Chromium
  // version of this fuzzer.
  // This number is chosen to match the default png_user_chunk_malloc_max.
  if (allocated_mem + size > 8000000)
    return NULL;

  void* ptr = malloc(size + sizeof(png_alloc_size_t));
  if (!ptr)
    return NULL;

  *(png_alloc_size_t*)ptr = size;
  allocated_mem += size;
  return (char*)ptr + sizeof(png_alloc_size_t);
}

void default_free(png_voidp ptr) {
  if (!ptr) return;
  void* raw_ptr = (char*)ptr - sizeof(png_alloc_size_t);
  png_alloc_size_t size = *(png_alloc_size_t*)raw_ptr;
  allocated_mem -= size;
  free(raw_ptr);
}

static const int kPngHeaderSize = 8;

//Below functions have been taken from the PNG book example for progressive image reading.
//Thus, its BSD license is included:

/*---------------------------------------------------------------------------

   rpng2 - progressive-model PNG display program                 readpng2.c

  ---------------------------------------------------------------------------

      Copyright (c) 1998-2007 Greg Roelofs.  All rights reserved.

      This software is provided "as is," without warranty of any kind,
      express or implied.  In no event shall the author or contributors
      be held liable for any damages arising in any way from the use of
      this software.

      The contents of this file are DUAL-LICENSED.  You may modify and/or
      redistribute this software according to the terms of one of the
      following two licenses (at your option):


      LICENSE 1 ("BSD-like with advertising clause"):

      Permission is granted to anyone to use this software for any purpose,
      including commercial applications, and to alter it and redistribute
      it freely, subject to the following restrictions:

      1. Redistributions of source code must retain the above copyright
         notice, disclaimer, and this list of conditions.
      2. Redistributions in binary form must reproduce the above copyright
         notice, disclaimer, and this list of conditions in the documenta-
         tion and/or other materials provided with the distribution.
      3. All advertising materials mentioning features or use of this
         software must display the following acknowledgment:

            This product includes software developed by Greg Roelofs
            and contributors for the book, "PNG: The Definitive Guide,"
            published by O'Reilly and Associates.

  ---------------------------------------------------------------------------*/
  enum rpng2_states {
    kPreInit = 0,
    kWindowInit,
    kDone
};

typedef unsigned char   uch;
typedef unsigned short  ush;
typedef unsigned long   ulg;

typedef struct _mainprog_info {
    double display_exponent;
    ulg width;
    ulg height;
    void *png_ptr;
    void *info_ptr;
    void (*mainprog_init)(void);
    void (*mainprog_display_row)(ulg row_num);
    void (*mainprog_finish_display)(void);
    uch *image_data;
    uch **row_pointers;
    jmp_buf jmpbuf;
    int passes;              /* not used */
    int pass;
    int rowbytes;
    int channels;
    int need_bgcolor;
#if (defined(__i386__) || defined(_M_IX86) || defined(__x86_64__))
    int nommxfilters;
    int nommxcombine;
    int nommxinterlace;
#endif
    int state;
    uch bg_red;
    uch bg_green;
    uch bg_blue;
} mainprog_info;


/* prototypes for public functions in readpng2.c */

void readpng2_version_info(void);


int readpng2_init(mainprog_info *mainprog_ptr);

int readpng2_decode_data(mainprog_info *mainprog_ptr, uch *rawbuf, ulg length);

void readpng2_cleanup(mainprog_info *mainprog_ptr);


void readpng2_error_handler(png_structp png_ptr, png_const_charp msg);
void readpng2_info_callback(png_structp png_ptr, png_infop info_ptr);
void readpng2_row_callback(png_structp png_ptr, png_bytep new_row,
                                  png_uint_32 row_num, int pass);
void readpng2_end_callback(png_structp png_ptr, png_infop info_ptr);

mainprog_info rpng2_info;

int readpng2_init(mainprog_info *mainprog_ptr)
{
    png_structp  png_ptr;       /* note:  temporary variables! */
    png_infop  info_ptr;


    /* could also replace libpng warning-handler (final NULL), but no need: */

    png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, mainprog_ptr,
      readpng2_error_handler, NULL);
    if (!png_ptr)
        return 4;   /* out of memory */

    info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        return 4;   /* out of memory */
    }


    /* we could create a second info struct here (end_info), but it's only
     * useful if we want to keep pre- and post-IDAT chunk info separated
     * (mainly for PNG-aware image editors and converters) */


    /* setjmp() must be called in every function that calls a PNG-reading
     * libpng function, unless an alternate error handler was installed--
     * but compatible error handlers must either use longjmp() themselves
     * (as in this program) or exit immediately, so here we are: */

    if (setjmp(mainprog_ptr->jmpbuf)) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return 2;
    }


    /* instead of doing png_init_io() here, now we set up our callback
     * functions for progressive decoding */

    png_set_progressive_read_fn(png_ptr, mainprog_ptr,
      readpng2_info_callback, readpng2_row_callback, readpng2_end_callback);


    /*
     * may as well enable or disable MMX routines here, if supported;
     *
     * to enable all:  mask = png_get_mmx_flagmask (
     *                   PNG_SELECT_READ | PNG_SELECT_WRITE, &compilerID);
     *                 flags = png_get_asm_flags (png_ptr);
     *                 flags |= mask;
     *                 png_set_asm_flags (png_ptr, flags);
     *
     * to disable all:  mask = png_get_mmx_flagmask (
     *                   PNG_SELECT_READ | PNG_SELECT_WRITE, &compilerID);
     *                  flags = png_get_asm_flags (png_ptr);
     *                  flags &= ~mask;
     *                  png_set_asm_flags (png_ptr, flags);
     */

#if (defined(__i386__) || defined(_M_IX86) || defined(__x86_64__)) && \
    defined(PNG_LIBPNG_VER) && (PNG_LIBPNG_VER >= 10200)
    /*
     * WARNING:  This preprocessor approach means that the following code
     *           cannot be used with a libpng DLL older than 1.2.0--the
     *           compiled-in symbols for the new functions will not exist.
     *           (Could use dlopen() and dlsym() on Unix and corresponding
     *           calls for Windows, but not portable...)
     */
    {
#ifdef PNG_ASSEMBLER_CODE_SUPPORTED
        png_uint_32 mmx_disable_mask = 0;
        png_uint_32 asm_flags, mmx_mask;
        int compilerID;

        if (mainprog_ptr->nommxfilters)
            mmx_disable_mask |= ( PNG_ASM_FLAG_MMX_READ_FILTER_SUB   \
                                | PNG_ASM_FLAG_MMX_READ_FILTER_UP    \
                                | PNG_ASM_FLAG_MMX_READ_FILTER_AVG   \
                                | PNG_ASM_FLAG_MMX_READ_FILTER_PAETH );
        if (mainprog_ptr->nommxcombine)
            mmx_disable_mask |= PNG_ASM_FLAG_MMX_READ_COMBINE_ROW;
        if (mainprog_ptr->nommxinterlace)
            mmx_disable_mask |= PNG_ASM_FLAG_MMX_READ_INTERLACE;
        asm_flags = png_get_asm_flags(png_ptr);
        png_set_asm_flags(png_ptr, asm_flags & ~mmx_disable_mask);


        /* Now query libpng's asm settings, just for yuks.  Note that this
         * differs from the querying of its *potential* MMX capabilities
         * in readpng2_version_info(); this is true runtime verification. */

        asm_flags = png_get_asm_flags(png_ptr);
        mmx_mask = png_get_mmx_flagmask(PNG_SELECT_READ | PNG_SELECT_WRITE,
          &compilerID);
        asm_flags &= (mmx_mask & ~( PNG_ASM_FLAG_MMX_READ_COMBINE_ROW  \
                                  | PNG_ASM_FLAG_MMX_READ_INTERLACE    \
                                  | PNG_ASM_FLAG_MMX_READ_FILTER_SUB   \
                                  | PNG_ASM_FLAG_MMX_READ_FILTER_UP    \
                                  | PNG_ASM_FLAG_MMX_READ_FILTER_AVG   \
                                  | PNG_ASM_FLAG_MMX_READ_FILTER_PAETH ));
#endif /* ?PNG_ASSEMBLER_CODE_SUPPORTED */
    }
#endif


    /* make sure we save our pointers for use in readpng2_decode_data() */

    mainprog_ptr->png_ptr = png_ptr;
    mainprog_ptr->info_ptr = info_ptr;


    /* and that's all there is to initialization */

    return 0;
}

/* returns 0 for success, 2 for libpng (longjmp) problem */

int readpng2_decode_data(mainprog_info *mainprog_ptr, uch *rawbuf, ulg length)
{
    png_structp png_ptr = (png_structp)mainprog_ptr->png_ptr;
    png_infop info_ptr = (png_infop)mainprog_ptr->info_ptr;


    /* setjmp() must be called in every function that calls a PNG-reading
     * libpng function */

    if (setjmp(mainprog_ptr->jmpbuf)) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        mainprog_ptr->png_ptr = NULL;
        mainprog_ptr->info_ptr = NULL;
        return 2;
    }


    /* hand off the next chunk of input data to libpng for decoding */

    png_process_data(png_ptr, info_ptr, rawbuf, length);

    return 0;
}




void readpng2_info_callback(png_structp png_ptr, png_infop info_ptr)
{
    mainprog_info  *mainprog_ptr;
    int  color_type, bit_depth;
    double  gamma;


    /* setjmp() doesn't make sense here, because we'd either have to exit(),
     * longjmp() ourselves, or return control to libpng, which doesn't want
     * to see us again.  By not doing anything here, libpng will instead jump
     * to readpng2_decode_data(), which can return an error value to the main
     * program. */


    /* retrieve the pointer to our special-purpose struct, using the png_ptr
     * that libpng passed back to us (i.e., not a global this time--there's
     * no real difference for a single image, but for a multithreaded browser
     * decoding several PNG images at the same time, one needs to avoid mixing
     * up different images' structs) */

    mainprog_ptr =(_mainprog_info *) png_get_progressive_ptr(png_ptr);

    if (mainprog_ptr == NULL) {         /* we be hosed */
        return;
        /*
         * Alternatively, we could call our error-handler just like libpng
         * does, which would effectively terminate the program.  Since this
         * can only happen if png_ptr gets redirected somewhere odd or the
         * main PNG struct gets wiped, we're probably toast anyway.  (If
         * png_ptr itself is NULL, we would not have been called.)
         */
    }


    /* this is just like in the non-progressive case */

    png_get_IHDR(png_ptr, info_ptr, (png_uint_32 *) (&mainprog_ptr->width),
      (png_uint_32 *) &mainprog_ptr->height, &bit_depth, &color_type, NULL, NULL, NULL);


    /* since we know we've read all of the PNG file's "header" (i.e., up
     * to IDAT), we can check for a background color here */

    if (mainprog_ptr->need_bgcolor &&
        png_get_valid(png_ptr, info_ptr, PNG_INFO_bKGD))
    {
        png_color_16p pBackground;

        /* it is not obvious from the libpng documentation, but this function
         * takes a pointer to a pointer, and it always returns valid red,
         * green and blue values, regardless of color_type: */
        png_get_bKGD(png_ptr, info_ptr, &pBackground);

        /* however, it always returns the raw bKGD data, regardless of any
         * bit-depth transformations, so check depth and adjust if necessary */
        if (bit_depth == 16) {
            mainprog_ptr->bg_red   = pBackground->red   >> 8;
            mainprog_ptr->bg_green = pBackground->green >> 8;
            mainprog_ptr->bg_blue  = pBackground->blue  >> 8;
        } else if (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 8) {
            if (bit_depth == 1)
                mainprog_ptr->bg_red = mainprog_ptr->bg_green =
                  mainprog_ptr->bg_blue = pBackground->gray? 255 : 0;
            else if (bit_depth == 2)
                mainprog_ptr->bg_red = mainprog_ptr->bg_green =
                  mainprog_ptr->bg_blue = (255/3) * pBackground->gray;
            else /* bit_depth == 4 */
                mainprog_ptr->bg_red = mainprog_ptr->bg_green =
                  mainprog_ptr->bg_blue = (255/15) * pBackground->gray;
        } else {
            mainprog_ptr->bg_red   = (uch)pBackground->red;
            mainprog_ptr->bg_green = (uch)pBackground->green;
            mainprog_ptr->bg_blue  = (uch)pBackground->blue;
        }
    }


    /* as before, let libpng expand palette images to RGB, low-bit-depth
     * grayscale images to 8 bits, transparency chunks to full alpha channel;
     * strip 16-bit-per-sample images to 8 bits per sample; and convert
     * grayscale to RGB[A] */

    if (color_type == PNG_COLOR_TYPE_PALETTE)
        png_set_expand(png_ptr);
    if (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 8)
        png_set_expand(png_ptr);
    if (png_get_valid(png_ptr, info_ptr, PNG_INFO_tRNS))
        png_set_expand(png_ptr);
    if (bit_depth == 16)
        png_set_strip_16(png_ptr);
    if (color_type == PNG_COLOR_TYPE_GRAY ||
        color_type == PNG_COLOR_TYPE_GRAY_ALPHA)
        png_set_gray_to_rgb(png_ptr);


    /* Unlike the basic viewer, which was designed to operate on local files,
     * this program is intended to simulate a web browser--even though we
     * actually read from a local file, too.  But because we are pretending
     * that most of the images originate on the Internet, we follow the recom-
     * mendation of the sRGB proposal and treat unlabelled images (no gAMA
     * chunk) as existing in the sRGB color space.  That is, we assume that
     * such images have a file gamma of 0.45455, which corresponds to a PC-like
     * display system.  This change in assumptions will have no effect on a
     * PC-like system, but on a Mac, SGI, NeXT or other system with a non-
     * identity lookup table, it will darken unlabelled images, which effec-
     * tively favors images from PC-like systems over those originating on
     * the local platform.  Note that mainprog_ptr->display_exponent is the
     * "gamma" value for the entire display system, i.e., the product of
     * LUT_exponent and CRT_exponent. */
      /*
    if (png_get_gAMA(png_ptr, info_ptr, &gamma))
        png_set_gamma(png_ptr, mainprog_ptr->display_exponent, gamma);
    else
        png_set_gamma(png_ptr, mainprog_ptr->display_exponent, 0.45455);
        */


    /* we'll let libpng expand interlaced images, too */

    mainprog_ptr->passes = png_set_interlace_handling(png_ptr);

    //png_set_gray_to_rgb(png_ptr);
    png_set_expand(png_ptr);
    png_set_packing(png_ptr);
    png_set_scale_16(png_ptr);
    png_set_tRNS_to_alpha(png_ptr);
    /* all transformations have been registered; now update info_ptr data and
     * then get rowbytes and channels */

    png_read_update_info(png_ptr, info_ptr);

    mainprog_ptr->rowbytes = (int)png_get_rowbytes(png_ptr, info_ptr);
    mainprog_ptr->channels = png_get_channels(png_ptr, info_ptr);


    /* Call the main program to allocate memory for the image buffer and
     * initialize windows and whatnot.  (The old-style function-pointer
     * invocation is used for compatibility with a few supposedly ANSI
     * compilers that nevertheless barf on "fn_ptr()"-style syntax.) */

    (*mainprog_ptr->mainprog_init)();


    /* and that takes care of initialization */

    return;
}





void readpng2_row_callback(png_structp png_ptr, png_bytep new_row,
                                  png_uint_32 row_num, int pass)
{
    mainprog_info  *mainprog_ptr;


    /* first check whether the row differs from the previous pass; if not,
     * nothing to combine or display */

    if (!new_row)
        return;


    /* retrieve the pointer to our special-purpose struct so we can access
     * the old rows and image-display callback function */

    mainprog_ptr = (_mainprog_info *) png_get_progressive_ptr(png_ptr);
     


    /* save the pass number for optional use by the front end */

    mainprog_ptr->pass = pass;


    /* have libpng either combine the new row data with the existing row data
     * from previous passes (if interlaced) or else just copy the new row
     * into the main program's image buffer */

    png_progressive_combine_row(png_ptr, mainprog_ptr->row_pointers[row_num],
      new_row);


    /* finally, call the display routine in the main program with the number
     * of the row we just updated */

    (*mainprog_ptr->mainprog_display_row)(row_num);


    /* and we're ready for more */

    return;
}





void readpng2_end_callback(png_structp png_ptr, png_infop info_ptr)
{
    mainprog_info  *mainprog_ptr;


    /* retrieve the pointer to our special-purpose struct */

    mainprog_ptr = (_mainprog_info *) png_get_progressive_ptr(png_ptr);


    /* let the main program know that it should flush any buffered image
     * data to the display now and set a "done" flag or whatever, but note
     * that it SHOULD NOT DESTROY THE PNG STRUCTS YET--in other words, do
     * NOT call readpng2_cleanup() either here or in the finish_display()
     * routine; wait until control returns to the main program via
     * readpng2_decode_data() */

    (*mainprog_ptr->mainprog_finish_display)();


    /* all done */

    return;
}





void readpng2_cleanup(mainprog_info *mainprog_ptr)
{
    png_structp png_ptr = (png_structp)mainprog_ptr->png_ptr;
    png_infop info_ptr = (png_infop)mainprog_ptr->info_ptr;

    if (png_ptr && info_ptr)
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);

    mainprog_ptr->png_ptr = NULL;
    mainprog_ptr->info_ptr = NULL;
}





void readpng2_error_handler(png_structp png_ptr, png_const_charp msg)
{
    mainprog_info  *mainprog_ptr;

    /* This function, aside from the extra step of retrieving the "error
     * pointer" (below) and the fact that it exists within the application
     * rather than within libpng, is essentially identical to libpng's
     * default error handler.  The second point is critical:  since both
     * setjmp() and longjmp() are called from the same code, they are
     * guaranteed to have compatible notions of how big a jmp_buf is,
     * regardless of whether _BSD_SOURCE or anything else has (or has not)
     * been defined. */


    mainprog_ptr = (_mainprog_info *) png_get_error_ptr(png_ptr);
    if (mainprog_ptr == NULL) {         /* we are completely hosed now */
        exit(99);
    }

    longjmp(mainprog_ptr->jmpbuf, 1);
}


void rpng2_x_init(void)
{
    ulg i;
    ulg rowbytes = rpng2_info.rowbytes;

    rpng2_info.image_data = (uch *)limited_malloc(rowbytes * rpng2_info.height);
    if (!rpng2_info.image_data) {
        readpng2_cleanup(&rpng2_info);
        return;
    }

    rpng2_info.row_pointers = (uch **)limited_malloc(rpng2_info.height * sizeof(uch *));
    if (!rpng2_info.row_pointers) {
        default_free(rpng2_info.image_data);
        rpng2_info.image_data = NULL;
        readpng2_cleanup(&rpng2_info);
        return;
    }

    for (i = 0;  i < rpng2_info.height;  ++i)
        rpng2_info.row_pointers[i] = rpng2_info.image_data + i*rowbytes;
}

int rows = 0;
int prevpass = -1;
ulg firstrow = 0;

void rpng2_x_display_row(ulg row)
{
    uch bg_red   = rpng2_info.bg_red;
    uch bg_green = rpng2_info.bg_green;
    uch bg_blue  = rpng2_info.bg_blue;
    uch *src, *src2=NULL;
    char *dest;
    uch r, g, b, a;
    ulg i, pixel;

/*---------------------------------------------------------------------------
    rows and firstrow simply track how many rows (and which ones) have not
    yet been displayed; alternatively, we could call XPutImage() for every
    row and not bother with the records-keeping.
  ---------------------------------------------------------------------------*/


    if (rpng2_info.pass != prevpass) {
        prevpass = rpng2_info.pass;
    }

    if (rows == 0)
        firstrow = row;   /* first row that is not yet displayed */

    ++rows;   /* count of rows received but not yet displayed */
    src = rpng2_info.image_data + row * rpng2_info.rowbytes;
    /*
    if (bg_image)
        src2 = bg_data + row * bg_rowbytes;
    */

    if (rpng2_info.channels == 3) {
        for (i = rpng2_info.width; i > 0; --i) {
            volatile ulg red = *src++;
            volatile ulg green = *src++;
            volatile ulg blue = *src++;
        }
    } else {
        for (i = rpng2_info.width; i > 0; --i) {
            volatile ulg r = *src++;
            volatile ulg g = *src++;
            volatile ulg b = *src++;
            volatile ulg a = *src++;/*
            if (bg_image) {
                volatile ulg bg_red = *src2++;
                volatile ulg bg_green = *src2++;
                volatile ulg bg_blue = *src2++;
            }*/
        }
    }
  }

void rpng2_x_finish_display(void)
{
    /* last row has already been displayed by rpng2_x_display_row(), so we
     * have nothing to do here except set a flag and let the user know that
     * the image is done */

    rpng2_info.state = kDone;
}
void rpng2_x_cleanup(void)
{
  /*
    if (bg_image && bg_data) {
        free(bg_data);
        bg_data = NULL;
    }
        */

    if (rpng2_info.image_data) {
        default_free(rpng2_info.image_data);
        rpng2_info.image_data = NULL;
    }

    if (rpng2_info.row_pointers) {
        default_free(rpng2_info.row_pointers);
        rpng2_info.row_pointers = NULL;
    }

}
#ifndef MAX
#  define MAX(a,b)  ((a) > (b)? (a) : (b))
#  define MIN(a,b)  ((a) < (b)? (a) : (b))
#endif

// Entry point for LibFuzzer.
// Roughly follows the libpng book example chapter 14 (not 13 as in the normal oss-fuzzer):
// http://www.libpng.org/pub/png/book/chapter14.html
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  allocated_mem = 0;
  rows = 0;
  prevpass = -1;
  firstrow = 0;
  memset(&rpng2_info, 0, sizeof(mainprog_info));

  if (size < 8) {
    return 0;
  }

  std::vector<unsigned char> v(data, data + size);
  if (!png_check_sig(v.data(), kPngHeaderSize)) {
    // not a PNG.
    return 0;
  }
  if (readpng2_init(&rpng2_info) != 0) {
    readpng2_cleanup(&rpng2_info);
    return 0;
  }



  rpng2_info.state = kPreInit;
  rpng2_info.mainprog_init = rpng2_x_init;
  rpng2_info.mainprog_display_row = rpng2_x_display_row;
  rpng2_info.mainprog_finish_display = rpng2_x_finish_display;


  size_t offset = 0;
  for (;;) {
    uch* inbuf = (uch *) (v.data() + offset);
    size_t incount = MIN(size - offset, 1024); 
    if (readpng2_decode_data(&rpng2_info, inbuf, incount) || rpng2_info.state == kDone || incount == 0) {
        break;
    }
    offset += incount;
  }

    rpng2_x_cleanup();
    readpng2_cleanup(&rpng2_info);
  return 0;
}

