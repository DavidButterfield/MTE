# MTE
**High-Performance Multithreaded Event Engine**  
A framework for running multithreaded event-driven applications  
*David A. Butterfield*

#### MTE Clients

 + [Usermode Compatibility (UMC)](https://github.com/DavidButterfield/usermode_compat
    "Usermode Compatibility for Linux Kernel Code (UMC)")
    &mdash; a shim for running some Linux kernel code in usermode

 + [iSCSI-SCST Storage Server Usermode Adaptation](https://github.com/DavidButterfield/SCST-Usermode-Adaptation
    "Usermode Compatibility for Linux Kernel Code (UMC)")
    &mdash; a port of the SCST iSCSI storage server to run entirely in usermode on an unmodified Linux kernel.
   [Paper describing the project in detail](https://davidbutterfield.github.io/SCST-Usermode-Adaptation/SCST_Usermode.html
    "Paper describing the project in detail")

#### Subdirectories

 include &mdash; header files for APIs implemented by MTE; also valgrind client
<PRE><SMALL>
   FILE        LinesOfCode  Contents
   ----        -----------  --------
   mtelib.h           60    API to initialize MTE
   sys_service.h     325    API for system services
   sys_debug.h       576    API for debugging services
   aio_service.h      81    API for storage AIO services
   valgrind.h               valgrind client interfaces
</SMALL></PRE>
   These files define the interface between MTE and its clients.  An example
   of an MTE client is the compatibility module for running Linux kernel code
   in usermode, used by the SCST Usermode Adaptation.  Both MTE and the client
   are compiled using these headers:  MTE as implementor and the client as
   consumer.

   These header files may be copied to /usr/include (only copy valgrind.h if
   you don't already have one there).  Alternatively the client Makefile may
   be configured to look in some other location for the MTE header files.

 src &mdash; source files for the Multithreaded Engine
<PRE><SMALL>
   FILE        LinesOfCode  Contents
   ----        -----------  --------
   Makefile
   mte_defines.h     184    Basic MTE definitions, macros, types
   mte_mttypes.h    1167    Multithread-Safe data types
   mte_util.h        161    support for MT types, time, sockets, random
   mte_util.c        365    support for MT types, time, sockets, random
   mte_debug.c       815    Symbol lookup, backtrace, sigdump, tcp_info
   mte_mem.h         236    Memory allocation interfaces
   mte_mem_impl.h   1091    Memory allocation implementation
   mte_mem.c         552    Memory allocation implementation
   mte_event_task.c 1022    Event thread support, epoll_wait(2) call
   mte_service.c     481    sys_service implementor API functions
   mtelib_aio.c      288    AIO service implementor API functions
   mte_aio.c         353    AIO service implementation
   mte_aio.h         143    AIO service implementation
   mte_aio_impl.h    201    AIO service implementation
</SMALL></PRE>
   These files make up the source for MTE.  "make all" compiles the source
   into libmte.a and libmte.so.  "make install" does that and then copies the
   libraries into /lib, also copying the header files into /usr/include
   (permission required on the destination directories for install to succeed).

