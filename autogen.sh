#! /bin/sh
glibtoolize 
aclocal \
&& automake --add-missing \
&& autoconf
