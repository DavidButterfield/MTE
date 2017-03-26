/* mtelib.h
 * Configure and get service handles for Multi-Threaded Engine services
 * Copyright 2015 David A. Butterfield
 */
#ifndef MTELIB_H
#define MTELIB_H
#include <inttypes.h>
#include <sys/types.h>

#include "sys_service.h"	/* Implementor */
//#include "network_service.h"	/* Implementor */
#include "aio_service.h"	/* Implementor */

/* Service handles */

extern sys_service_handle_t	MTE_sys_service_get(void);
extern error_t			MTE_sys_service_put(sys_service_handle_t);

extern aio_service_handle_t	MTE_aio_service_get(void);
extern error_t			MTE_aio_service_put(aio_service_handle_t);

// extern network_service_handle_t	MTE_network_service_get(void);
// extern error_t			MTE_network_service_put(network_service_handle_t);

/* Service configurations are passed to the services' _init() functions */

/* MTE system service configuration */
typedef struct MTE_sys_service_cfg {
    /* empty */
} * MTE_sys_service_cfg_t;


/* MTE async disk I/O service configuration */
typedef struct MTE_aio_service_cfg {
    uint32_t			max_ops_outstanding;
    uint32_t			min_ops_outstanding;
    uint32_t			max_ops_per_dispatch;
} * MTE_aio_service_cfg_t;

#define MTE_AIO_MAXIOV 256  //XXXX TUNE


/* MTE network service configuration */
#include <netinet/ip.h>

typedef struct MTE_network_service_cfg {
    /* empty */
} * MTE_network_service_cfg_t;

/* Listener for asynchronous (high-performance) connections */
typedef struct MTE_network_listener_cfg {
    /* empty */
} * MTE_network_listener_cfg_t;

/* Listener for synchronous (simple-usage) connections */
typedef struct MTE_network_sync_listener_cfg {
    /* empty */
} * MTE_network_sync_listener_cfg_t;

#endif /* MTELIB_H */
