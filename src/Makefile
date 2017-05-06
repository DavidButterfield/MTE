# src/mte/Makefile
# Copyright 2016 David A. Butterfield
# Makefile for the Multithreaded Engine

####################  Enable most compiler warnings  ####################

WFLAGS_WARN += -Wall
WFLAGS_WARN += -Wextra
WFLAGS_WARN += -Wundef
WFLAGS_WARN += -Winit-self
WFLAGS_WARN += -Wstrict-prototypes
WFLAGS_WARN += -Wlogical-op
WFLAGS_WARN += -Wjump-misses-init
WFLAGS_WARN += -Wcast-align
WFLAGS_WARN += -Wold-style-definition 
WFLAGS_WARN += -Wredundant-decls
WFLAGS_WARN += -Wbad-function-cast
WFLAGS_WARN += -Wmissing-declarations
WFLAGS_WARN += -Wmissing-prototypes
WFLAGS_WARN += -Wnested-externs
WFLAGS_WARN += -Wmissing-include-dirs
WFLAGS_WARN += -Wunsafe-loop-optimizations
WFLAGS_WARN += -Wcast-qual
WFLAGS_WARN += -Wformat=2
WFLAGS_WARN += -Wshadow
WFLAGS_WARN += -Wswitch-default
WFLAGS_WARN += -Wswitch-enum
WFLAGS_WARN += -Wwrite-strings

## too noisy
# WFLAGS_WARN += -Wpointer-arith
# WFLAGS_WARN += -Wconversion
# WFLAGS_WARN += -Wsign-conversion

WFLAGS_INHIBIT += -Wno-unused-parameter		# silly

MY_CFLAGS += $(WFLAGS_WARN) $(WFLAGS_INHIBIT)

EXTRA_CFLAGS += $(MY_CFLAGS)
export EXTRA_CFLAGS

############################################################

# MTE_CFLAGS += -DVALGRIND	    # Enable special program behavior for valgrind
# MTE_CFLAGS += -DNVALGRIND	    # Disable compiling valgrind hooks in program

# MTE_CFLAGS += -DDEBUG
# MTE_CFLAGS += -DTRACE_TRACE
# MTE_CFLAGS += -DTRACE_VERBOSE

MTE_CFLAGS += -O3 -fno-strict-aliasing	#XXX
# MTE_CFLAGS += -O2
# MTE_CFLAGS += -O1
# MTE_CFLAGS += -O0

# MTE_CFLAGS += -DOPTIMIZED	# disable most of the memory checks remaining when !DEBUG

# If the services and mte headers are not in /usr/include, this is where they are
EXTRA_INCLUDE =	../include

MTE_CFLAGS += -I$(EXTRA_INCLUDE)

CFLAGS += -g -fPIC -D_GNU_SOURCE $(MTE_CFLAGS)

############################################################

MTE_LDFLAGS    +=     -d -z now -O 1 -E
MTE_GCCLDFLAGS += -Wl,-d,-z,now,-O,1,-E

SRCS_D = mte_service.c mte_event_task.c mte_mem.c mte_util.c mte_debug.c mtelib_aio.c mte_aio.c
OBJS_D = $(SRCS_D:.c=.o)

LIBS = libmte.a libmte.so

all: $(LIBS)
	@echo "***** use 'make install' or manually install shared library and include files (permission required) *****"

install: $(LIBS)
	$(MAKE) -C . /lib/libmte.so
	$(MAKE) -C . /lib/libmte.a
	cp $(EXTRA_INCLUDE)/*.h /usr/include

/lib/libmte.so:	libmte.so
	cp $< $@

/lib/libmte.a:	libmte.a
	cp $< $@

libmte.a: .depend $(OBJS_D)
	$(LD) $(MTE_LDFLAGS) -r -o $@ $(OBJS_D)

libmte.so:.depend $(OBJS_D)
	gcc $(MTE_GCCLDFLAGS) -fPIC -shared -o $@ $(OBJS_D) -lpthread -laio -ldl -lc

ifeq (.depend,$(wildcard .depend))
-include .depend
endif

%.o: %.c Makefile
	$(CC) -c -o $(@) $(CFLAGS) $(<)

.depend:
	$(CC) -M $(CFLAGS) $(SRCS_D) >$(@)

clean:
	rm -f *.o $(LIBS) .depend

extraclean: clean
	rm -f *.orig *.rej tags cscope.out
