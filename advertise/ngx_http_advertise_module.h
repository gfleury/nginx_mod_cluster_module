//
//  ngx_http_advertise_module.h
//  mod_cluster-nginx
//
//  Created by George Fleury on 12/04/14.
//  Copyright (c) 2014 George Fleury. All rights reserved.
//

#ifndef mod_cluster_nginx_ngx_http_advertise_module_h
#define mod_cluster_nginx_ngx_http_advertise_module_h


#define MA_BSIZE                4096
#define MA_SSIZE                1024
#define MA_DEFAULT_ADVPORT      23364
#define MA_DEFAULT_GROUP        (u_char *)"224.0.1.105"
#define MA_TM_RESOLUTION        NGX_TIME_C(100000)
#define MA_DEFAULT_ADV_FREQ     ngx_time_from_sec(10)
#define MA_TM_MAINTAIN_STEP     10

/**
 * Multicast Time to Live (ttl) for a advertise transmission.
 */
#define MA_ADVERTISE_HOPS       10

/**
 * Advertise protocol types
 */
#define MA_ADVERTISE_SERVER     0
#define MA_ADVERTISE_STATUS     1

#define ngx_http_get_module_cf_ctx(r, module)  (r)->ctx[module.ctx_index]
#define ngx_http_set_cf_ctx(r, c, module)      r->ctx[module.ctx_index] = c;


/**
 * Advertise mode enumeration.
 */
typedef enum {
    ma_advertise_off,
    ma_advertise_on
} ma_advertise_e;

#endif
