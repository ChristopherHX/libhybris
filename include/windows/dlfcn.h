/* User functions for run-time dynamic loading.
   Copyright (C) 1995-2019 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef	_DLFCN_H
#define	_DLFCN_H 1

#define __need_size_t
#include <stddef.h>

#include "msvc.h"
/* Collect various system dependent definitions and declarations.  */
// #include <bits/dlfcn.h>
#define __USE_GNU

#ifdef __USE_GNU
/* If the first argument of `dlsym' or `dlvsym' is set to RTLD_NEXT
   the run-time address of the symbol called NAME in the next shared
   object is returned.  The "next" relation is defined by the order
   the shared objects were loaded.  */
# define RTLD_NEXT	((void *) -1l)

/* If the first argument to `dlsym' or `dlvsym' is set to RTLD_DEFAULT
   the run-time address of the symbol called NAME in the global scope
   is returned.  */
# define RTLD_DEFAULT	((void *) 0)


/* Type for namespace indeces.  */
typedef long int Lmid_t;

/* Special namespace ID values.  */
# define LM_ID_BASE	0	/* Initial namespace.  */
# define LM_ID_NEWLM	-1	/* For dlmopen: request new namespace.  */
#endif


#ifdef __cplusplus
extern "C" {
#endif

#ifdef __USE_GNU
/* Structure containing information about object searched using
   `dladdr'.  */
typedef struct
{
  const char *dli_fname;	/* File name of defining object.  */
  void *dli_fbase;		/* Load address of that object.  */
  const char *dli_sname;	/* Name of nearest symbol.  */
  void *dli_saddr;		/* Exact value of nearest symbol.  */
} Dl_info;

/* These are the possible values for the FLAGS argument to `dladdr1'.
   This indicates what extra information is stored at *EXTRA_INFO.
   It may also be zero, in which case the EXTRA_INFO argument is not used.  */
enum
  {
    /* Matching symbol table entry (const ElfNN_Sym *).  */
    RTLD_DL_SYMENT = 1,

    /* The object containing the address (struct link_map *).  */
    RTLD_DL_LINKMAP = 2
  };

/* These are the possible values for the REQUEST argument to `dlinfo'.  */
enum
  {
    /* Treat ARG as `lmid_t *'; store namespace ID for HANDLE there.  */
    RTLD_DI_LMID = 1,

    /* Treat ARG as `struct link_map **';
       store the `struct link_map *' for HANDLE there.  */
    RTLD_DI_LINKMAP = 2,

    RTLD_DI_CONFIGADDR = 3,	/* Unsupported, defined by Solaris.  */

    /* Treat ARG as `Dl_serinfo *' (see below), and fill in to describe the
       directories that will be searched for dependencies of this object.
       RTLD_DI_SERINFOSIZE fills in just the `dls_cnt' and `dls_size'
       entries to indicate the size of the buffer that must be passed to
       RTLD_DI_SERINFO to fill in the full information.  */
    RTLD_DI_SERINFO = 4,
    RTLD_DI_SERINFOSIZE = 5,

    /* Treat ARG as `char *', and store there the directory name used to
       expand $ORIGIN in this shared object's dependency file names.  */
    RTLD_DI_ORIGIN = 6,

    RTLD_DI_PROFILENAME = 7,	/* Unsupported, defined by Solaris.  */
    RTLD_DI_PROFILEOUT = 8,	/* Unsupported, defined by Solaris.  */

    /* Treat ARG as `size_t *', and store there the TLS module ID
       of this object's PT_TLS segment, as used in TLS relocations;
       store zero if this object does not define a PT_TLS segment.  */
    RTLD_DI_TLS_MODID = 9,

    /* Treat ARG as `void **', and store there a pointer to the calling
       thread's TLS block corresponding to this object's PT_TLS segment.
       Store a null pointer if this object does not define a PT_TLS
       segment, or if the calling thread has not allocated a block for it.  */
    RTLD_DI_TLS_DATA = 10,

    RTLD_DI_MAX = 10
  };


/* This is the type of elements in `Dl_serinfo', below.
   The `dls_name' member points to space in the buffer passed to `dlinfo'.  */
typedef struct
{
  char *dls_name;		/* Name of library search path directory.  */
  unsigned int dls_flags;	/* Indicates where this directory came from. */
} Dl_serpath;

/* This is the structure that must be passed (by reference) to `dlinfo' for
   the RTLD_DI_SERINFO and RTLD_DI_SERINFOSIZE requests.  */
typedef struct
{
  size_t dls_size;		/* Size in bytes of the whole buffer.  */
  unsigned int dls_cnt;		/* Number of elements in `dls_serpath'.  */
  Dl_serpath dls_serpath[1];	/* Actually longer, dls_cnt elements.  */
} Dl_serinfo;
#endif /* __USE_GNU */


#define dlopen(filename, flag) (void*)LoadLibraryA(filename)
#define dlsym(handle, symbol) (void*)GetProcAddress((HMODULE)handle, symbol)
#define dlclose(handle) FreeLibrary((HMODULE)handle)
#define dladdr(a,b) 0
#define dlerror() 0

#ifdef __cplusplus
}
#endif

#endif	/* dlfcn.h */
