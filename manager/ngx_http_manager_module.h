//
//  ngx_http_manager_module.h
//  mod_cluster-nginx
//
//  Created by George Fleury on 12/04/14.
//  Copyright (c) 2014 George Fleury. All rights reserved.
//

#ifndef mod_cluster_nginx_ngx_http_manager_module_h
#define mod_cluster_nginx_ngx_http_manager_module_h


#define DEFMAXCONTEXT   200
#define DEFMAXNODE      300
#define DEFMAXHOST      300
#define DEFMAXSESSIONID 600 /* it has performance/security impact */
#define DEFMAXJGROUPSID  300
#define MAXMESSSIZE     1024

#define TIMESESSIONID   60
#define TIMEDOMAIN    300                    /* after 5 minutes the sessionid have probably timeout */

/* Error messages */
#define TYPESYNTAX 1
#define SMESPAR "SYNTAX: Can't parse message"
#define SBALBIG "SYNTAX: Balancer field too big"
#define SBAFBIG "SYNTAX: A field is too big"
#define SROUBIG "SYNTAX: JVMRoute field too big"
#define SROUBAD "SYNTAX: JVMRoute can't be empty"
#define SDOMBIG "SYNTAX: LBGroup field too big"
#define SHOSBIG "SYNTAX: Host field too big"
#define SPORBIG "SYNTAX: Port field too big"    
#define STYPBIG "SYNTAX: Type field too big"
#define SALIBAD "SYNTAX: Alias without Context"
#define SCONBAD "SYNTAX: Context without Alias"
#define SBADFLD "SYNTAX: Invalid field \"%s\" in message"
#define SMISFLD "SYNTAX: Mandatory field(s) missing in message"
#define SCMDUNS "SYNTAX: Command is not supported"
#define SMULALB "SYNTAX: Only one Alias in APP command"
#define SMULCTB "SYNTAX: Only one Context in APP command"
#define SREADER "SYNTAX: %V can't read POST data"

#define SJIDBIG "SYNTAX: JGroupUuid field too big"
#define SJDDBIG "SYNTAX: JGroupData field too big"
#define SJIDBAD "SYNTAX: JGroupUuid can't be empty"

#define TYPEMEM 2
#define MNODEUI "MEM: Can't update or insert node"
#define MNODERM "MEM: Old node still exist"
#define MBALAUI "MEM: Can't update or insert balancer"
#define MNODERD "MEM: Can't read node"
#define MHOSTRD "MEM: Can't read host alias"
#define MHOSTUI "MEM: Can't update or insert host alias"
#define MCONTUI "MEM: Can't update or insert context"
#define MJBIDRD "MEM: Can't read JGroupId"
#define MJBIDUI "MEM: Can't update or insert JGroupId"

/* Protocol version supported */
#define VERSION_PROTOCOL "0.2.1"

/* range of the commands */
#define RANGECONTEXT 0
#define RANGENODE    1
#define RANGEDOMAIN  2

/* define HAVE_CLUSTER_EX_DEBUG to have extented debug in mod_cluster */
#define HAVE_CLUSTER_EX_DEBUG 0

#include "../include/slotmem.h"
#include "../include/node.h"
#include "../include/sessionid.h"
#include "../include/context.h"
#include "../include/balancer.h"
#include "../include/host.h"
#include "../include/domain.h"
#include "../include/jgroupsid.h"
#include "sharedmem_util.h"

struct mem {
    ap_slotmem_t *slotmem;
    slotmem_storage_method *storage;
    int num;
    ngx_pool_t *p;
    ngx_int_t laststatus;
};

#ifndef MEM_T
typedef struct mem mem_t;
#define MEM_T
#endif

typedef struct {
    ngx_str_t                      key_start;
    ngx_str_t                      schema;
    ngx_str_t                      host_header;
    ngx_str_t                      port;
    ngx_str_t                      uri;
} ngx_http_proxy_vars_t;


typedef struct {
    ngx_http_upstream_conf_t       upstream;

    ngx_array_t                   *flushes;
    ngx_array_t                   *body_set_len;
    ngx_array_t                   *body_set;
    ngx_array_t                   *headers_set_len;
    ngx_array_t                   *headers_set;
    ngx_hash_t                     headers_set_hash;

    ngx_array_t                   *headers_source;

    ngx_array_t                   *proxy_lengths;
    ngx_array_t                   *proxy_values;

    ngx_array_t                   *redirects;
    ngx_array_t                   *cookie_domains;
    ngx_array_t                   *cookie_paths;

    ngx_str_t                      body_source;

    ngx_str_t                      method;
    ngx_str_t                      location;
    ngx_str_t                      url;

#if (NGX_HTTP_CACHE)
    ngx_http_complex_value_t       cache_key;
#endif

    ngx_http_proxy_vars_t          vars;

    ngx_flag_t                     redirect;

    ngx_uint_t                     http_version;

    ngx_uint_t                     headers_hash_max_size;
    ngx_uint_t                     headers_hash_bucket_size;

#if (NGX_HTTP_SSL)
    ngx_uint_t                     ssl;
    ngx_uint_t                     ssl_protocols;
    ngx_str_t                      ssl_ciphers;
#endif
   int max_peers_number;
   time_t updatetime;    
   unsigned int tableversion;
} ngx_http_proxy_loc_conf_t;



typedef struct mod_manager_config {
    /* base name for the shared memory */
    ngx_str_t basefilename;
    /* max number of context supported */
    int maxcontext;
    /* max number of node supported */
    int maxnode;
    /* max number of host supported */
    int maxhost;
    /* max number of session supported */
    int maxsessionid;
    /* max number of jgroupsid supported */
    int maxjgroupsid;

    /* version, the version is increased each time the node update logic is called */
    unsigned int tableversion;

    /* Should be the slotmem persisted (1) or not (0) */
    int persistent;

    /* check for nonce in the command logic */
    int nonce;

    /* default name for balancer */
    ngx_str_t balancername;

    /* allow aditional display */
    int allow_display;
    /* allow command logic */
    int allow_cmd;
    /* don't context in first status page */
    int reduce_display;
    /* maximum message size */
    size_t maxmesssize;
    /* Enable MCPM receiver */
    int enable_mcpm_receive;
    
    ngx_event_t *clean_timer;
    
    ngx_http_proxy_loc_conf_t  *plcf[DEFMAXCONTEXT];
    
} mod_manager_config;


/* Context table copy for local use */
struct proxy_context_table
{
	int sizecontext;
	int* contexts;
	contextinfo_t* context_info;
};
typedef struct proxy_context_table proxy_context_table;


/* VHost table copy for local use */
struct proxy_vhost_table
{
	int sizevhost;
	int* vhosts;
	hostinfo_t* vhost_info;
};
typedef struct proxy_vhost_table proxy_vhost_table;

/* Balancer table copy for local use */
struct proxy_balancer_table
{
	int sizebalancer;
	int* balancers;
	balancerinfo_t* balancer_info;
};
typedef struct proxy_balancer_table proxy_balancer_table;

/* Node table copy for local use */
struct proxy_node_table
{
	int sizenode;
	int* nodes;
	nodeinfo_t*  node_info;
};
typedef struct proxy_node_table proxy_node_table;

/* table of node and context selected by find_node_context_host() */
struct node_context
{
        int node;
        int context;
};
typedef struct node_context node_context;

typedef struct {
    ngx_http_status_t              status;
    ngx_http_chunked_t             chunked;
    ngx_http_proxy_vars_t          vars;
    off_t                          internal_body_length;

    ngx_uint_t                     head;  /* unsigned  head:1 */
    ngx_http_proxy_loc_conf_t  *plcf;
    u_char                      sticky_data[SESSIONIDSZ];
    u_char                      JVMRoute[JVMROUTESZ];
    balancerinfo_t              *balancer;
    ngx_uint_t                  direct_upstream;
} ngx_http_proxy_ctx_t;

balancerinfo_t *loc_search_balancer(balancerinfo_t *balancer);


#endif
