# aclocal.m4 generated automatically by aclocal 1.6.3 -*- Autoconf -*-

# Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002
# Free Software Foundation, Inc.
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

AC_DEFUN([AC_FUNC_GCC_VISIBILITY],
  [AC_CACHE_CHECK(whether __attribute__((visibility())) is supported,
		  libc_cv_visibility_attribute,
		  [cat > conftest.c <<EOF
		   int foo __attribute__ ((visibility ("hidden"))) = 1;
		   int bar __attribute__ ((visibility ("protected"))) = 1;
EOF
		  libc_cv_visibility_attribute=no
		  if ${CC-cc} -Werror -S conftest.c -o conftest.s \
			>/dev/null 2>&1; then
		    if grep '\.hidden.*foo' conftest.s >/dev/null; then
		      if grep '\.protected.*bar' conftest.s >/dev/null; then
			libc_cv_visibility_attribute=yes
		      fi
		    fi
		  fi
		  rm -f conftest.[cs]
		  ])
   if test $libc_cv_visibility_attribute = yes; then
     AC_DEFINE(HAVE_VISIBILITY_ATTRIBUTE)
   fi
  ])

