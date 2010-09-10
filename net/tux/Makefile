#
# Makefile for TUX
#

obj-$(CONFIG_TUX) += tux.o

tux-y := accept.o input.o userspace.o cachemiss.o output.o \
	redirect.o postpone.o logger.o proto_http.o proto_ftp.o \
	proc.o main.o mod.o abuf.o times.o directory.o gzip.o

tux-$(subst m,y,$(CONFIG_TUX_EXTCGI)) += cgi.o extcgi.o

