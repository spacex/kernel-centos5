# Set the following to `true' to make a debuggable build.
# Leave this set to `false' for production use.
DEBUG = true


ROOT =		mod-extract
VERSION =	0.1
INSTALL_DIR =	/usr/local/bin
RELEASE_NAME =	$(ROOT)-$(VERSION)

CC = gcc

INCLUDES = 
CFLAGS = -g -O -Wall

OBJS =	mod-extract.o

all: $(ROOT)

$(ROOT): $(OBJS)
	$(CC) $(LDFLAGS) -o $(ROOT) $(OBJS) -lbfd -liberty $(LIB_OBJS) $(ARCH_LIB_OBJS)

.c.o:
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@

clean:
	-rm $(OBJS) $(ROOT)
