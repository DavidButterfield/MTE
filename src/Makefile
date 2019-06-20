# src/mte/Makefile
# Copyright 2016 David A. Butterfield
# Makefile for the Multithreaded Engine

# MY_CFLAGS += -DVALGRIND -DARENA_DISABLE=1	# Enable special program behavior for valgrind
# MY_CFLAGS += -DNVALGRIND			# Disable compiling valgrind hooks in program

MY_CFLAGS += -DDEBUG
# MY_CFLAGS += -fsanitize=undefined
# MY_CFLAGS += -DNDEBUG

# MY_CFLAGS += -DTRACE_TRACE
# MY_CFLAGS += -DTRACE_VERBOSE

# MY_CFLAGS += -O0
MY_CFLAGS += -Og
# MY_CFLAGS += -O1
# MY_CFLAGS += -O2
# MY_CFLAGS += -O3
# MY_CFLAGS += -DOPTIMIZED	# disable most of the memory checks remaining when !DEBUG

#######################  Enable most compiler warnings  #######################

# Warnings enabled by a real kernel build
WFLAGS_WARN += -Wall
WFLAGS_WARN += -Wmissing-prototypes
WFLAGS_WARN += -Wstrict-prototypes
WFLAGS_WARN += -Wundef

# Warnings passed by MTE
WFLAGS_WARN += -Wextra
WFLAGS_WARN += -Wjump-misses-init
WFLAGS_WARN += -Wlogical-op
WFLAGS_WARN += -Wcast-align
WFLAGS_WARN += -Wold-style-definition 
WFLAGS_WARN += -Wmissing-include-dirs
WFLAGS_WARN += -Wfloat-conversion
WFLAGS_WARN += -Wmissing-declarations
WFLAGS_WARN += -Wnested-externs
WFLAGS_WARN += -Wunsafe-loop-optimizations

WFLAGS_WARN += -Winit-self
WFLAGS_WARN += -Wswitch-enum
WFLAGS_WARN += -Wredundant-decls
WFLAGS_WARN += -Wformat=2

# This only warns if -fstrict-aliasing is enabled (e.g. by -O2), in which case the warning is important
WFLAGS_WARN += -Wstrict-aliasing

## Some of each of these in MTE code
# WFLAGS_WARN += -Wconversion
# WFLAGS_WARN += -Wsign-conversion
# WFLAGS_WARN += -Wpointer-arith

# More warnings passed by MTE
WFLAGS_WARN += -Wwrite-strings
WFLAGS_WARN += -Wswitch-default
WFLAGS_WARN += -Wcast-qual
WFLAGS_WARN += -Wbad-function-cast			# 1 in linux/kernel.h when compiling SCST/DRBD
WFLAGS_WARN += -Wshadow					# kernel.h, bitops.h when compiling SCST/DRBD

### silly
WFLAGS_INHIBIT += -Wno-unused-parameter

MY_CFLAGS += $(WFLAGS_WARN) $(WFLAGS_INHIBIT)

###############################################################################

MTE_CFLAGS += -ggdb -fPIC -fno-omit-frame-pointer -D_GNU_SOURCE
MTE_CFLAGS += -I../include
MTE_CFLAGS += $(MY_CFLAGS)
MTE_CFLAGS += $(EXTRA_CFLAGS)	    # imported if existing

MTE_LDFLAGS    +=     -d -z now -O 1 -E
MTE_GCCLDFLAGS += -Wl,-d,-z,now,-O,1,-E

SRCS_D = mte_service.c mte_event_task.c mte_mem.c mte_util.c mte_debug.c mtelib_aio.c mte_aio.c
OBJS_D = $(SRCS_D:.c=.o)

LIBS = libmte.a libmte.so

all: $(LIBS) cscope.out

install: $(LIBS)
	$(MAKE) -C . /lib/libmte.so
	$(MAKE) -C . /lib/libmte.a
	cp ../include/*.h /usr/include

cscope:	cscope.out

/lib/libmte.so:	libmte.so
	cp $< $@

/lib/libmte.a:	libmte.a
	cp $< $@

libmte.a: .depend $(OBJS_D)
	$(LD) $(MTE_LDFLAGS) -r -o $@ $(OBJS_D)

libmte.so:.depend $(OBJS_D)
	gcc $(MTE_GCCLDFLAGS) -fPIC -shared -o $@ $(OBJS_D) -lpthread -laio -ldl \
		-L/usr/lib/x86_64-linux-gnu -lubsan \
		-lc \

ifeq (.depend,$(wildcard .depend))
-include .depend
endif

%.o: %.c Makefile
	$(CC) -c -o $(@) $(MTE_CFLAGS) $(<)

.depend:
	$(CC) -M $(MTE_CFLAGS) $(SRCS_D) >$(@)

cleanish:
	rm -f *.o .depend

clean: cleanish
	rm -f $(LIBS) tags cscope.out

extraclean: clean
	rm -f *.orig *.rej

cscope.out:
	@cscope -b -c -R -s..
	@ctags        -R   ..

.PHONY:	all install clean extraclean cscope
