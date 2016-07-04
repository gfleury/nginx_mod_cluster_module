//
//  ngx_http_advertise_module.c
//  mod_cluster-nginx
//
//  Created by George Fleury on 11/04/14.
//  Copyright (c) 2014 George Fleury. All rights reserved.
//


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>

#include <pthread.h>

#include "ngx_http_advertise_module.h"
#include "../include/ngx_utils.h"

typedef struct mod_advertise_config {
    u_char *ma_advertise_adrs;
    u_char *ma_advertise_adsi;
    u_char *ma_advertise_srvm;
    u_char *ma_advertise_srvh;
    u_char *ma_advertise_srvhostname;
    u_char *ma_advertise_srvs;
    u_char *ma_advertise_srvi;
    u_char *ma_advertise_uuid;

    u_char *ma_advertise_skey;

    ngx_int_t ma_bind_set;
    u_char *ma_bind_adrs;
    u_char *ma_bind_adsi;
    ngx_int_t ma_bind_port;

    ngx_int_t ma_advertise_port;
    ngx_int_t ma_advertise_srvp;
    ma_advertise_e ma_advertise_mode;
    uint64_t ma_advertise_freq;
} mod_advertise_config;

static ngx_int_t ma_advertise_run = 0;
static ngx_int_t ma_advertise_stat = 0;
static volatile uint64_t ma_sequence = 0;

/* Advertise sockets */
static int ma_mgroup_socket = 0;
static ngx_sockaddr_t ma_mgroup_sa;
static ngx_sockaddr_t ma_listen_sa;
static ngx_sockaddr_t ma_niface_sa;

/* Parent and child manager thread statuses */
static volatile int is_mp_running = 0;
static volatile int is_mp_created = 0;

/*
 * Server global data
 */
typedef struct ma_global_data_t {
    unsigned char ssalt[MD5_DIGESTSIZE];
    uuid_t suuid;
    u_char srvid[UUID_FORMATTED_LENGTH + 2];
} ma_global_data_t;

/*
 * Global data instance
 * For parent, registered in process pool
 */
static ma_global_data_t *magd = NULL;


static char *ngx_http_advertise(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_advertise_group(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_advertise_frequency(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_advertise_seckey(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_advertise_manageurl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_advertise_bindaddr(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ma_group_join(const u_char *addr, ngx_int_t port, const u_char *bindaddr, ngx_int_t bindport, ngx_conf_t *cf);

static ngx_command_t ngx_http_advertise_commands[] = {
    { ngx_string("ServerAdvertise"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1 | NGX_CONF_TAKE2,
        ngx_http_advertise,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL},

    { ngx_string("AdvertiseGroup"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_http_advertise_group,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL},

    { ngx_string("AdvertiseFrequency"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_http_advertise_frequency,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL},

    { ngx_string("AdvertiseSecurityKey"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_http_advertise_seckey,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL},

    { ngx_string("AdvertiseManagerUrl"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_http_advertise_manageurl,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL},

    { ngx_string("AdvertiseBindAddress"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_http_advertise_bindaddr,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL},

    ngx_null_command
};

static void *ngx_http_advertise_create_conf(ngx_conf_t *cf);
static char *ngx_http_advertise_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_advertise_post_config_hook(ngx_conf_t *cf);
static ngx_int_t ngx_http_advertise_child_init_hook(ngx_cycle_t *cycle);
static void ngx_http_advertise_process_cleanup_hook(ngx_cycle_t *cycle);

static ngx_http_module_t ngx_http_advertise_module_ctx = {
    NULL, /* preconfiguration */
    ngx_http_advertise_post_config_hook, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    ngx_http_advertise_create_conf, /* create server configuration */
    ngx_http_advertise_merge_conf, /* merge server configuration */

    NULL, /* create location configuration */
    NULL /* merge location configuration */
};


ngx_module_t ngx_http_advertise_module = {
    NGX_MODULE_V1,
    &ngx_http_advertise_module_ctx, /* module context */
    ngx_http_advertise_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    ngx_http_advertise_child_init_hook, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    ngx_http_advertise_process_cleanup_hook, /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *ngx_http_advertise(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    mod_advertise_config *mconf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_advertise_module);

    ngx_uint_t n_args = cf->args->nelts - 1;

    ngx_str_t *value = cf->args->elts;

    ngx_str_t *arg = NULL, *opt = NULL;


    if (mconf->ma_advertise_srvs)
        return "Duplicate ServerAdvertise directives are not allowed";

    if (n_args >= 1)
        arg = &value[1];

    if (n_args >= 2)
        opt = &value[2];

    if (ngx_strcasecmp(arg->data, (u_char *) "Off") == 0)
        mconf->ma_advertise_mode = ma_advertise_off;
    else if (ngx_strcasecmp(arg->data, (u_char *) "On") == 0)
        mconf->ma_advertise_mode = ma_advertise_on;
    else
        return "ServerAdvertise must be Off or On";
    if (opt) {
        const u_char *p = (u_char *) ngx_strstr(opt, "://");
        if (p) {
            mconf->ma_advertise_srvm = ngx_pstrndup(cf->pool, opt, p - opt->data);
            opt->data = (u_char *) p + 3;
        }
        if (ngx_parse_addr_port(&mconf->ma_advertise_srvs,
                &mconf->ma_advertise_srvi,
                &mconf->ma_advertise_srvp,
                opt->data, cf->pool) != NGX_OK ||
                !mconf->ma_advertise_srvs ||
                !mconf->ma_advertise_srvp)
            return "Invalid ServerAdvertise Address";
    }


    return NGX_CONF_OK;
}

static char *ngx_http_advertise_group(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    mod_advertise_config *mconf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_advertise_module);

    ngx_uint_t n_args = cf->args->nelts - 1;

    ngx_str_t *value = cf->args->elts;

    ngx_str_t *arg = NULL;

    if (mconf->ma_advertise_port != MA_DEFAULT_ADVPORT &&
            mconf->ma_advertise_adrs != MA_DEFAULT_GROUP)
        return "Duplicate AdvertiseGroup directives are not allowed";

    if (n_args >= 1)
        arg = &value[1];
    else
        return NGX_CONF_ERROR;

    if (ngx_parse_addr_port(&mconf->ma_advertise_adrs,
            &mconf->ma_advertise_adsi,
            &mconf->ma_advertise_port,
            arg->data, cf->pool) != NGX_OK)
        return "Invalid AdvertiseGroup address";
    if (!mconf->ma_advertise_adrs)
        return "Missing Ip part from AdvertiseGroup address";
    if (!mconf->ma_advertise_port)
        mconf->ma_advertise_port = MA_DEFAULT_ADVPORT;



    return NGX_CONF_OK;

}

static char *ngx_http_advertise_frequency(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    mod_advertise_config *mconf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_advertise_module);

    ngx_uint_t n_args = cf->args->nelts - 1;

    ngx_str_t *value = cf->args->elts;

    ngx_str_t *arg = NULL;

    ngx_time_t s = {0, 0, 0};

    const u_char *p;

    if (mconf->ma_advertise_freq != MA_DEFAULT_ADV_FREQ)
        return "Duplicate AdvertiseFrequency directives are not allowed";

    if (n_args >= 1)
        arg = &value[1];
    else
        return NGX_CONF_ERROR;

    if ((p = (u_char *) ngx_strchr(arg->data, '.')) || (p = (u_char *) ngx_strchr(arg->data, ',')))
        s.msec = ngx_atoi((u_char *) p + 1, ngx_strlen(p + 1));

    s.sec = ngx_atoi(arg->data, ngx_strlen(arg->data));

    mconf->ma_advertise_freq = s.sec * NGX_USEC_PER_SEC + s.msec * NGX_TIME_C(1000);
    if (mconf->ma_advertise_freq == 0)
        return "Invalid AdvertiseFrequency value";

    return NGX_CONF_OK;

}

static char *ngx_http_advertise_seckey(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    mod_advertise_config *mconf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_advertise_module);

    ngx_uint_t n_args = cf->args->nelts - 1;

    ngx_str_t *value = cf->args->elts;

    ngx_str_t *arg = NULL;


    if (mconf->ma_advertise_skey != NULL)
        return "Duplicate AdvertiseSecurityKey directives are not allowed";

    if (n_args >= 1)
        arg = &value[1];
    else
        return NGX_CONF_ERROR;

    mconf->ma_advertise_skey = ngx_pstrdup2(cf->pool, arg);

    return NGX_CONF_OK;
}

static char *ngx_http_advertise_manageurl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    mod_advertise_config *mconf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_advertise_module);

    ngx_uint_t n_args = cf->args->nelts - 1;

    ngx_str_t *value = cf->args->elts;

    ngx_str_t *arg = NULL;



    if (mconf->ma_advertise_srvh != NULL)
        return "Duplicate AdvertiseManagerUrl directives are not allowed";

    if (n_args >= 1)
        arg = &value[1];
    else
        return NGX_CONF_ERROR;

    mconf->ma_advertise_srvh = ngx_pstrdup2(cf->pool, arg);


    return NGX_CONF_OK;
}

static char *ngx_http_advertise_bindaddr(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    mod_advertise_config *mconf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_advertise_module);

    ngx_uint_t n_args = cf->args->nelts - 1;

    ngx_str_t *value = cf->args->elts;

    ngx_str_t *arg = NULL;


    if (mconf->ma_bind_set)
        return "Duplicate AdvertiseBindAddress directives are not allowed";


    if (n_args >= 1)
        arg = &value[1];
    else
        return NGX_CONF_ERROR;


    if (ngx_parse_addr_port(&mconf->ma_bind_adrs,
            &mconf->ma_bind_adsi,
            &mconf->ma_bind_port,
            arg->data, cf->pool) != NGX_OK)
        return "Invalid AdvertiseBindAddress address";

    if (!mconf->ma_bind_adrs)
        return "Missing Ip part from AdvertiseBindAddress address";

    if (!mconf->ma_bind_port)
        mconf->ma_bind_port = MA_DEFAULT_ADVPORT;

    mconf->ma_bind_set = 1;


    return NGX_CONF_OK;
}

static void *ngx_http_advertise_create_conf(ngx_conf_t *cf) { // static void *create_advertise_server_config(apr_pool_t *p, server_rec *s)

    mod_advertise_config *mconf = ngx_pcalloc(cf->pool, sizeof (*mconf));

    if (mconf == NULL) {
        return NGX_CONF_ERROR;
    }

    /* Set default values */
    mconf->ma_advertise_adrs = MA_DEFAULT_GROUP;
    mconf->ma_advertise_adsi = NULL;
    mconf->ma_advertise_srvm = NULL;
    mconf->ma_advertise_srvh = NULL;
    mconf->ma_advertise_srvs = NULL;
    mconf->ma_advertise_srvi = NULL;
    mconf->ma_advertise_uuid = NULL;
    mconf->ma_advertise_srvhostname = NULL;

    mconf->ma_advertise_skey = NULL;

    mconf->ma_bind_set = 0;
    mconf->ma_bind_adrs = NULL;
    mconf->ma_bind_adsi = NULL;
    mconf->ma_bind_port = MA_DEFAULT_ADVPORT;

    mconf->ma_advertise_port = MA_DEFAULT_ADVPORT;
    mconf->ma_advertise_srvp = 0;
    mconf->ma_advertise_mode = ma_advertise_on;
    mconf->ma_advertise_freq = MA_DEFAULT_ADV_FREQ;

    return mconf;

}

static char *ngx_http_advertise_merge_conf(ngx_conf_t *cf, void *parent, void *child) {
    return NGX_CONF_OK;
}

static void *parent_thread(void *data);

static ngx_int_t ngx_http_advertise_post_config_hook(ngx_conf_t *cf) { //static void register_hooks(apr_pool_t *p)

    ngx_err_t rv;
    ngx_pool_t *pproc = cf->pool;

    mod_advertise_config *mconf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_advertise_module);


    if (!magd) {
        if (!(magd = ngx_pcalloc(pproc, sizeof (ma_global_data_t)))) {        
            ngx_log_error(NGX_LOG_CRIT, cf->log, 0, "mod_advertise: Unable to ngx_pcalloc magd struct");
            return NGX_ERROR;
        }
    }

    if (mconf->ma_advertise_skey) {
        ngx_md5_t mc;
        ngx_md5_init(&mc);
        ngx_md5_update(&mc, mconf->ma_advertise_skey, ngx_strlen(mconf->ma_advertise_skey));
        ngx_md5_final(magd->ssalt, &mc);
    } else {
        /* If security key is not configured, the digest is calculated from zero bytes */
        memset(magd->ssalt, '\0', MD5_DIGESTSIZE);
    }
    uuid_create(&magd->suuid);
    magd->srvid[0] = '/';
    snpuid(&magd->srvid[1], sizeof (magd->srvid), magd->suuid);
    if (!mconf->ma_advertise_srvh)
        mconf->ma_advertise_srvh = magd->srvid;
    /* Check if we have advertise set */
    if (mconf->ma_advertise_mode != ma_advertise_off &&
            mconf->ma_advertise_adrs) {
        rv = ma_group_join(mconf->ma_advertise_adrs, mconf->ma_advertise_port, mconf->ma_bind_adrs, mconf->ma_bind_port, cf);
        if (rv != NGX_OK) {
            ngx_log_error(NGX_LOG_CRIT, cf->log, 0, "mod_advertise: multicast join failed for %s:%d.", mconf->ma_advertise_adrs, mconf->ma_advertise_port);
            ma_advertise_run = 0;
        } else {
            ma_advertise_run = 1;
            ma_advertise_stat = 200;
        }
    }
   
    /* Fill default values */
    if (!mconf->ma_advertise_srvm) {
        ngx_str_t t = ngx_string("http");
        mconf->ma_advertise_srvm = ngx_pstrdup2(cf->pool, &t);
    }
   
    if (!mconf->ma_advertise_srvhostname) {
        mconf->ma_advertise_srvhostname = ngx_pstrdup2(cf->pool, &cf->cycle->hostname);
    }

    if (mconf->ma_advertise_srvs == NULL && cf) {
        /*
         * That is not easy just use ServerAdvertise with the server parameter
         * if the code below doesn't work
         */
        u_char *ptr = NULL;        
        
        if (cf->cycle->hostname.data != NULL) {
            u_char port[] = ":80";

            ptr = ngx_pstrdup(cf->pool, &cf->cycle->hostname);
            ptr = ngx_pstrcat(cf->pool, ptr, port, NULL);
        }

        rv = ngx_parse_addr_port(&mconf->ma_advertise_srvs,
                &mconf->ma_advertise_srvi,
                &mconf->ma_advertise_srvp,
                ptr, cf->pool);
        if (rv != NGX_OK || !mconf->ma_advertise_srvs ||
                !mconf->ma_advertise_srvp) {
            ngx_log_error(NGX_LOG_CRIT, cf->log, 0,
                    "mod_advertise: Invalid ServerAdvertise Address %s",
                    ptr);
            return rv;
        }
    }

    /* prevent X-Manager-Address: (null):0  */
    if (!mconf->ma_advertise_srvs || !mconf->ma_advertise_srvp) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, 0, "mod_advertise: ServerAdvertise Address or Port not defined, Advertise disabled!!!");
        return NGX_OK;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_advertise_child_init_hook(ngx_cycle_t *cycle) {

    ngx_err_t rv;
    pthread_t tp;

    mod_advertise_config *mconf = NULL;

    if (ngx_get_conf(cycle->conf_ctx, ngx_http_module)) {
        ngx_http_conf_ctx_t *ctx = (ngx_http_conf_ctx_t *) ngx_get_conf(cycle->conf_ctx, ngx_http_module);
        mconf = ngx_http_get_module_srv_conf(ctx, ngx_http_advertise_module);
    }
    
    if (!mconf) {
        ngx_log_error(NGX_LOG_CRIT, cycle->log, 0, "mod_advertise: Unable to get config instance");
        return NGX_ERROR;
    }

    /* Create parent management thread */
    if (!is_mp_running)
        is_mp_running = 1;
    else
        return NGX_OK;


    rv = pthread_create(&tp, NULL, parent_thread, mconf);
    if (rv != NGX_OK) {
        ngx_log_error(NGX_LOG_CRIT, cycle->log, 0, "mod_advertise: parent apr_thread_create");
        return rv;
    }

    pthread_detach(tp);


    return NGX_OK;

}

static void ma_group_leave() {
    if (ma_mgroup_socket) {
        ngx_mcast_leave(&ma_mgroup_socket, &ma_mgroup_sa, NULL, NULL);
        close(ma_mgroup_socket);
        ma_mgroup_socket = 0;
    }
}

static ngx_int_t ma_group_join(const u_char *addr, ngx_int_t port, const u_char *bindaddr, ngx_int_t bindport, ngx_conf_t *cf) {

    ngx_int_t rv;   
    struct in_addr iaddr;   
    unsigned char one = 1;
    u_char *service = ngx_itoa(cf->pool, port);
    u_char *bind_service = ngx_itoa(cf->pool, bindport);

    if ((rv = ngx_sockaddr_getinfo(addr, service, 0, &ma_mgroup_sa)) != NGX_OK) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, 0,
                "mod_advertise: ma_group_join ngx_sockaddr_info_get(%s:%d) failed: %s", addr, port, gai_strerror(rv));
        return rv;
    }

    if ((rv = ngx_sockaddr_getinfo(bindaddr, bind_service, ma_mgroup_sa.family, &ma_listen_sa)) != NGX_OK) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, 0,
                "mod_advertise: ma_group_join apr_sockaddr_info_get(%s:%d) failed: %s", bindaddr, bindport, gai_strerror(rv));
        return rv;
    }

    if ((rv = ngx_sockaddr_getinfo(NULL, (u_char *) "0", ma_mgroup_sa.family, &ma_niface_sa)) != NGX_OK) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, 0,
                "mod_advertise: ma_group_join apr_sockaddr_info_get(0.0.0.0:0) failed: %s", gai_strerror(rv));
        return rv;
    }

    if ((rv = ngx_socket_create(&ma_mgroup_socket, ma_mgroup_sa.family, SOCK_DGRAM, IPPROTO_UDP)) != NGX_OK) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, 0,
                "mod_advertise: ma_group_join apr_socket_create failed");
        return rv;
    }

    if ((rv = ngx_socket_opt_set(ma_mgroup_socket, SO_REUSEADDR, 1)) != NGX_OK) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, 0,
                "mod_advertise: ma_group_join apr_socket_opt_set failed");
        return rv;
    }

    if ((rv = ngx_socket_bind(&ma_mgroup_socket, &ma_listen_sa)) != NGX_OK) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, 0,
                "mod_advertise: ma_group_join apr_socket_bind failed");
        return rv;
    }
    iaddr.s_addr = INADDR_ANY; // use DEFAULT interface
  
    // Set the outgoing interface to DEFAULT
 
    setsockopt(ma_mgroup_socket, IPPROTO_IP, IP_MULTICAST_IF, &iaddr,
              sizeof(struct in_addr));
    
    // send multicast traffic to myself too
    setsockopt(ma_mgroup_socket, IPPROTO_IP, IP_MULTICAST_LOOP,
                       &one, sizeof(unsigned char));

    if ((rv = ngx_mcast_join(&ma_mgroup_socket, &ma_mgroup_sa, &ma_niface_sa, NULL)) != NGX_OK) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, 0,
                "mod_advertise: ma_group_join apr_mcast_join failed");

        if ((rv = ngx_mcast_loopback(ma_mgroup_socket, 1)) != NGX_OK) {
            ngx_log_error(NGX_LOG_CRIT, cf->log, 0,
                    "mod_advertise: ma_group_join apr_mcast_loopback failed");
            close(ma_mgroup_socket);
            return rv;
        }
    }

    if ((rv = ngx_mcast_hops(ma_mgroup_socket, MA_ADVERTISE_HOPS)) != NGX_OK) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, 0,
                "mod_advertise: ma_group_join apr_mcast_hops failed");
        /* Due a bug in apr (fixed by r1309332) apr_mcast_hops may fail */
        ngx_mcast_leave(&ma_mgroup_socket, &ma_mgroup_sa, NULL, NULL);
        close(ma_mgroup_socket);
        return rv;
    }
    return NGX_OK;
}

#define MA_ADVERTISE_SERVER_FMT \
"HTTP/1.0 %s" CRLF \
"Date: %s" CRLF \
"Sequence: %" NGX_INT64_T_FMT CRLF \
"Digest: %s" CRLF \
"Server: %s" CRLF

static const char *hex = "0123456789abcdef";

ngx_status_t ma_advertise_server(mod_advertise_config *mconf, int type) {
    u_char buf[MA_BSIZE];
    u_char dat[RFC822_DATE_LEN];
    u_char add[40];
    unsigned char msig[MD5_DIGESTSIZE];
    unsigned char ssig[MD5_DIGESTSIZE * 2 + 1];
    const u_char *asl;
    u_char *p = buf, *pu;
    int i, c = 0;
    size_t l = MA_BSIZE - 8;
    size_t n = 0;
    ngx_md5_t md;
    // mod_advertise_config *mconf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_advertise_module);

    ma_sequence++;
    if (ma_sequence < 1)
        ma_sequence = 1;
    ngx_sprintf(buf, "%" NGX_INT64_T_FMT, ma_sequence);
    ngx_recent_rfc822_date(dat, time(NULL), RFC822_DATE_LEN);
    asl = ngx_get_status_line(ma_advertise_stat);

    /* Create MD5 digest
     * salt + date + sequence + srvid
     */
    ngx_md5_init(&md);
    ngx_md5_update(&md, magd->ssalt, MD5_DIGESTSIZE);
    ngx_md5_update(&md, dat, ngx_strlen(dat));
    ngx_md5_update(&md, buf, ngx_strlen(buf));
    ngx_md5_update(&md, magd->srvid + 1, ngx_strlen(magd->srvid) - 1);
    ngx_md5_final(msig, &md);
    /* Convert MD5 digest to hex string */
    for (i = 0; i < MD5_DIGESTSIZE; i++) {
        ssig[c++] = hex[msig[i] >> 4];
        ssig[c++] = hex[msig[i] & 0x0F];
    }
    ssig[c] = '\0';
    pu = ngx_snprintf(p, l, MA_ADVERTISE_SERVER_FMT, asl, dat, ma_sequence, ssig, magd->srvid + 1);
    n = (pu - p);
    if (type == MA_ADVERTISE_SERVER) {
        u_char *ma_advertise_srvs = mconf->ma_advertise_srvs;
        if (ngx_strchr(ma_advertise_srvs, ':') != NULL) {
            ngx_snprintf(add, 40, "[%s]", mconf->ma_advertise_srvs);
            ma_advertise_srvs = add;
        }
        l -= n;
        pu = ngx_snprintf(p + n, l,
                "X-Manager-Address: %s:%ui" CRLF
                "X-Manager-Url: %s" CRLF
                "X-Manager-Protocol: %s" CRLF
                "X-Manager-Host: %s" CRLF,
                ma_advertise_srvs,
                mconf->ma_advertise_srvp,
                mconf->ma_advertise_srvh,
                mconf->ma_advertise_srvm,
                mconf->ma_advertise_srvhostname);
        n += (pu - (p + n));

    }
    p = ngx_strncat(p, (u_char *) CRLF, 2);
    n += 2;
    return ngx_socket_sendto(ma_mgroup_socket, &ma_mgroup_sa, 0, buf, &n);
}

static void ngx_http_advertise_process_cleanup_hook(ngx_cycle_t *cycle) {

    int advertise_run = ma_advertise_run;

    mod_advertise_config *mconf = NULL;

    if (ngx_get_conf(cycle->conf_ctx, ngx_http_module)) {
        ngx_http_conf_ctx_t *ctx = (ngx_http_conf_ctx_t *) ngx_get_conf(cycle->conf_ctx, ngx_http_module);
        mconf = ngx_http_get_module_srv_conf(ctx, ngx_http_advertise_module);
    }
    
    is_mp_running = 0;
    ma_advertise_run = 0;
    if (advertise_run) {
        ma_advertise_stat = 403;
        ma_advertise_server(mconf, MA_ADVERTISE_STATUS);
    }
    if (is_mp_created) {
        ngx_usleep(1000);
        /* Wait for the parent maintenance thread to finish */
        while (is_mp_created) {
            ngx_usleep(MA_TM_RESOLUTION);
        }
    }
    if (advertise_run) {
        ma_advertise_stat = 410;
        ma_advertise_server(mconf, MA_ADVERTISE_STATUS);
        ma_group_leave();
    }

    magd = NULL;


}

static void *parent_thread(void *data) {
    static int current_status = 0;
    int f_time = 1;
    ngx_interval_time_t a_step = 0;

    mod_advertise_config *mconf = (mod_advertise_config *) data; //ngx_http_conf_get_module_srv_conf(cf, ngx_http_advertise_module);
    is_mp_created = 1;

    while (is_mp_running) {
        ngx_usleep(MA_TM_RESOLUTION);
        if (!is_mp_running)
            break;
        if (ma_advertise_run) {
            a_step += MA_TM_RESOLUTION;
            if (current_status != ma_advertise_stat) {
                /* Force advertise on status change */
                current_status = ma_advertise_stat;
                f_time = 1;
            }
            if (a_step >= mconf->ma_advertise_freq || f_time) {
                /* Run advertise */
                ma_advertise_server(mconf, MA_ADVERTISE_SERVER);
                a_step = 0;
                f_time = 0;
            }
            if (!is_mp_running)
                break;
        }
        /* TODO: Implement actual work for parent thread */
        if (!is_mp_running)
            break;
    }
    is_mp_created = 0;

    return NULL;
}

/*
 * Provide information for "status" logic
 */
void advertise_info(ngx_http_request_t *r, ngx_buf_t *b) {

    mod_advertise_config *mconf = ngx_http_get_module_srv_conf(r, ngx_http_advertise_module);
    
    ngx_http_core_srv_conf_t *cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    
    ngx_bprintf(b, "Server: %V ", cscf->server_name);
    
    if (mconf->ma_advertise_srvhostname != NULL) {
        ngx_bprintf(b, " Advertising on Group %s Port %d ", mconf->ma_advertise_adrs, mconf->ma_advertise_port);
        ngx_bprintf(b, "for %s://%s:%d every %d seconds<br/>", mconf->ma_advertise_srvm, mconf->ma_advertise_srvs, mconf-> ma_advertise_srvp, mconf->ma_advertise_freq);
    } else {
        ngx_bprintf(b, "<br/>");
    }

}