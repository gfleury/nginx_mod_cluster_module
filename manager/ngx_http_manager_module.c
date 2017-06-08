//
//  ngx_http_manager_module.c
//  mod_cluster-nginx
//
//  Created by George Fleury on 11/04/14.
//  Copyright (c) 2014 George Fleury. All rights reserved.
//


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_manager_module.h"
#include "ngx_http_upstream_fair_module.h"

#include "../include/ngx_utils.h"

/* helper for the handling of the Alias: host1,... Context: context1,... */
struct cluster_host {
    u_char *host;
    u_char *context;
    struct cluster_host *next;
};

/* Global Vars */
static u_char balancer_nonce[UUID_FORMATTED_LENGTH + 2];
static slotmem_storage_method *storage = NULL;
//static balancer_method *balancerhandler = NULL;
extern void advertise_info(ngx_http_request_t *r, ngx_buf_t *b);

/* shared memory */
static mem_t *contextstatsmem = NULL;
static mem_t *nodestatsmem = NULL;
static mem_t *hoststatsmem = NULL;
static mem_t *balancerstatsmem = NULL;
static mem_t *sessionidstatsmem = NULL;
static mem_t *domainstatsmem = NULL;
static mem_t *jgroupsidstatsmem = NULL;

/* Config CMDs Functions */
static char *ngx_cmd_manager_mcpm_receive_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_cmd_manager_info_handler_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* Do the work functions */
static ngx_int_t ngx_http_manager_info_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_manager_handler(ngx_http_request_t *r);

static ngx_command_t ngx_http_manager_commands[] = {
    { ngx_string("Maxcontext"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(mod_manager_config, maxcontext),
        NULL},

    { ngx_string("Maxhost"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(mod_manager_config, maxhost),
        NULL},

    { ngx_string("Maxnode"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(mod_manager_config, maxnode),
        NULL},

    { ngx_string("Maxsessionid"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(mod_manager_config, maxsessionid),
        NULL},

    { ngx_string("Maxjgroupsid"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(mod_manager_config, maxsessionid),
        NULL},

    { ngx_string("MemManagerFile"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(mod_manager_config, basefilename),
        NULL},

    { ngx_string("ManagerBalancerName"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(mod_manager_config, balancername),
        NULL},

    { ngx_string("PersistSlots"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(mod_manager_config, persistent),
        NULL},

    { ngx_string("CheckNonce"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(mod_manager_config, nonce),
        NULL},

    { ngx_string("AllowDisplay"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(mod_manager_config, allow_display),
        NULL},

    { ngx_string("AllowCmd"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(mod_manager_config, allow_cmd),
        NULL},

    { ngx_string("ReduceDisplay"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(mod_manager_config, reduce_display),
        NULL},

    { ngx_string("MaxMCMPMessSize"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(mod_manager_config, maxmesssize),
        NULL},

    { ngx_string("EnableMCPMReceive"),
        NGX_HTTP_SRV_CONF | NGX_CONF_NOARGS,
        ngx_cmd_manager_mcpm_receive_enable,
        0,
        0,
        NULL},

    { ngx_string("ModManagerInfo"),
        NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
        ngx_cmd_manager_info_handler_enable,
        0,
        0,
        NULL},

    ngx_null_command
};

static ngx_int_t ngx_http_manager_postconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_manager_preconfiguration(ngx_conf_t *cf);
static void *ngx_http_module_manager_create_manager_config(ngx_conf_t *cf);
static ngx_int_t ngx_http_manager_child_init(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_manager_module_init(ngx_cycle_t *cycle);

static ngx_http_module_t ngx_http_manager_module_ctx = {
    ngx_http_manager_preconfiguration, /* preconfiguration */
    ngx_http_manager_postconfiguration, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    ngx_http_module_manager_create_manager_config, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL /* merge location configuration */
};


ngx_module_t ngx_http_manager_module = {
    NGX_MODULE_V1,
    &ngx_http_manager_module_ctx, /* module context */
    ngx_http_manager_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    ngx_http_manager_module_init, /* init module */
    ngx_http_manager_child_init, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

char *ngx_http_proxy_merge_loc_conf(ngx_conf_t *cf, ngx_http_proxy_loc_conf_t *prev, ngx_http_proxy_loc_conf_t *conf);

static char *ngx_cmd_manager_mcpm_receive_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    mod_manager_config *mconf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_manager_module);
    ngx_http_core_loc_conf_t *clcf;
    int i;

    if (mconf)
        mconf->enable_mcpm_receive = 1;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_manager_handler;

    /*
     * Configure proxy structures
     */
    for (i = 0; i < DEFMAXCONTEXT; i++) {
        ngx_http_proxy_loc_conf_t *plcf = mconf->plcf[i];

        if (ngx_http_proxy_merge_loc_conf(cf, plcf, plcf) != NGX_CONF_OK) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_http_proxy_merge_loc_conf failed");
            return NGX_CONF_ERROR;
        }
        plcf->http_version = NGX_HTTP_VERSION_11;
    }

    return NGX_CONF_OK;
}

static char *ngx_cmd_manager_info_handler_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf;


    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_manager_info_handler;

    return NGX_CONF_OK;
}

static u_char *balancer_nonce_string(ngx_http_request_t *r) {
    u_char *ret = (u_char*) "";
    mod_manager_config *mconf = ngx_http_get_module_srv_conf(r, ngx_http_manager_module);

    if (mconf->nonce) {
        ngx_str_t n = ngx_string("nonce=");
        ret = ngx_pstrndup3(r->pool, n.data, n.len);
        ret = ngx_pstrcat(r->pool, ret, balancer_nonce, "&", NULL);
    }

    return ret;
}

static ngx_int_t loc_read_node(int ids, nodeinfo_t **node) {
    return (get_node(nodestatsmem, node, ids));
}

static int loc_get_ids_used_node(int *ids) {
    return (get_ids_used_node(nodestatsmem, ids));
}

static int loc_get_max_size_node() {
    if (nodestatsmem)
        return (get_max_size_node(nodestatsmem));
    else
        return 0;
}

static int loc_get_max_size_sessionid() {
    if (sessionidstatsmem)
        return (get_max_size_sessionid(sessionidstatsmem));
    else
        return 0;
}

static int loc_get_max_size_balancer() {
    if (balancerstatsmem)
        return (get_max_size_balancer(balancerstatsmem));
    else
        return 0;
}

static int loc_get_max_size_context() {
    if (contextstatsmem)
        return (get_max_size_context(contextstatsmem));
    else
        return 0;
}

static int loc_get_max_size_host() {
    if (hoststatsmem)
        return (get_max_size_host(hoststatsmem));
    else
        return 0;
}

static int loc_get_max_size_jgroupsid() {
    if (jgroupsidstatsmem)
        return (get_max_size_jgroupsid(jgroupsidstatsmem));
    else
        return 0;
}


/*
 * routines for the domain_storage_method
 */
static ngx_int_t loc_read_domain(int ids, domaininfo_t **domain) {
    return (get_domain(domainstatsmem, domain, ids));
}
static int loc_get_ids_used_domain(int *ids) {
    return(get_ids_used_domain(domainstatsmem, ids)); 
}
static int loc_get_max_size_domain() {
    if (domainstatsmem)
        return(get_max_size_domain(domainstatsmem));
    else
        return 0;
}
static ngx_int_t loc_remove_domain(domaininfo_t *domain) {
    return (remove_domain(domainstatsmem, domain));
}
static ngx_int_t loc_insert_update_domain(domaininfo_t *domain) {
    return (insert_update_domain(domainstatsmem, domain));
}
static ngx_int_t loc_find_domain(domaininfo_t **domain, const char *route, const char *balancer) {
    return (find_domain(domainstatsmem, domain, route, balancer));
}
static const struct  domain_storage_method domain_storage = {
    loc_read_domain,
    loc_get_ids_used_domain,
    loc_get_max_size_domain,
    loc_remove_domain,
    loc_insert_update_domain,
    loc_find_domain
};

/*
 * routines for the host_storage_method
 */
static ngx_int_t loc_read_host(int ids, hostinfo_t **host) {
    return (get_host(hoststatsmem, host, ids));
}

static int loc_get_ids_used_host(int *ids) {
    return (get_ids_used_host(hoststatsmem, ids));
}
static const struct host_storage_method host_storage = {
    loc_read_host,
    loc_get_ids_used_host,
    loc_get_max_size_host
};

const struct host_storage_method *get_host_storage() {
    return &host_storage;
}

/* Check is the nodes (in shared memory) were modified since last
 * call to worker_nodes_are_updated().
 * return codes:
 *   0 : No update of the nodes since last time.
 *   x: The version has changed the local table need to be updated.
 */
static unsigned int loc_worker_nodes_need_update(unsigned int actual) {
    int size;
    unsigned int last = 0;

    size = loc_get_max_size_node();
    if (size == 0)
        return 0; /* broken */

    last = get_version_node(nodestatsmem);
 
    if (last != actual)
        return last;
    
    return (0);
}

/* Store the last version update in the proccess config */
static int loc_worker_nodes_are_updated(unsigned int last) {
    //mod_manager_config *mconf = ap_get_module_config(s->module_config, &manager_module);
    //mconf->tableversion = last;
    return (0);
}

static ngx_int_t loc_remove_node(nodeinfo_t *node) {
    return (remove_node(nodestatsmem, node));
}

static ngx_int_t loc_find_node(nodeinfo_t **node, const u_char *route) {
    return (find_node(nodestatsmem, node, route));
}


/* Remove the virtual hosts and contexts corresponding the node */
static void loc_remove_host_context(int node, ngx_pool_t *pool) {
    /* for read the hosts */
    int i;
    int size = loc_get_max_size_host();
    int id[DEFMAXHOST];
    int sizecontext = loc_get_max_size_context();
    int idcontext[DEFMAXCONTEXT];

    if (size == 0)
        return;
    //id = ngx_palloc(pool, sizeof (int) * size);
    //idcontext = ngx_palloc(pool, sizeof (int) * sizecontext);
    size = get_ids_used_host(hoststatsmem, id);
    for (i = 0; i < size; i++) {
        hostinfo_t *ou;

        if (get_host(hoststatsmem, &ou, id[i]) != NGX_OK)
            continue;
        if (ou->node == node)
            remove_host(hoststatsmem, ou);
    }

    sizecontext = get_ids_used_context(contextstatsmem, idcontext);
    for (i = 0; i < sizecontext; i++) {
        contextinfo_t *context;
        if (get_context(contextstatsmem, &context, idcontext[i]) != NGX_OK)
            continue;
        if (context->node == node)
            remove_context(contextstatsmem, context);
    }
}


static const struct node_storage_method node_storage = {
    loc_read_node,
    loc_get_ids_used_node,
    loc_get_max_size_node,
    loc_worker_nodes_need_update,
    loc_worker_nodes_are_updated,
    loc_remove_node,
    loc_find_node,
    loc_remove_host_context,
};

const struct node_storage_method *get_node_storage() {
    return &node_storage;
}

/*
 * routines for the context_storage_method
 */
static ngx_int_t loc_read_context(int ids, contextinfo_t **context) {
    return (get_context(contextstatsmem, context, ids));
}

static int loc_get_ids_used_context(int *ids) {
    return (get_ids_used_context(contextstatsmem, ids));
}

static void loc_lock_contexts() {
    lock_contexts(contextstatsmem);
}

static void loc_unlock_contexts() {
    unlock_contexts(contextstatsmem);
}

static unsigned int loc_context_need_update(unsigned int actual) {
    int size;
    unsigned int last = 0;

    size = loc_get_max_size_context();
    if (size == 0)
        return 0; /* broken */

    last = get_version_context(contextstatsmem);
 
    if (last != actual)
        return last;
    
    return (0);
}

static const struct context_storage_method context_storage = {
    loc_read_context,
    loc_get_ids_used_context,
    loc_get_max_size_context,
    loc_lock_contexts,
    loc_unlock_contexts, 
    loc_context_need_update
};

const struct context_storage_method *get_context_storage() {
    return &context_storage;
}

/*
 * routines for the balancer_storage_method
 */
balancerinfo_t *loc_search_balancer(balancerinfo_t *balancer) {
    return (read_balancer(balancerstatsmem, balancer));
}

static ngx_int_t loc_read_balancer(int ids, balancerinfo_t **balancer) {
    return (get_balancer(balancerstatsmem, balancer, ids));
}

static int loc_get_ids_used_balancer(int *ids) {
    return (get_ids_used_balancer(balancerstatsmem, ids));
}

static const struct balancer_storage_method balancer_storage = {
    loc_read_balancer,
    loc_get_ids_used_balancer,
    loc_get_max_size_balancer
};

const struct balancer_storage_method *get_balancer_storage() {
    return &balancer_storage;
}

/*
 * routines for the sessionid_storage_method
 */
static ngx_int_t loc_read_sessionid(int ids, sessionidinfo_t **sessionid) {
    return (get_sessionid(sessionidstatsmem, sessionid, ids));
}

static int loc_get_ids_used_sessionid(int *ids) {
    return (get_ids_used_sessionid(sessionidstatsmem, ids));
}

static ngx_int_t loc_remove_sessionid(sessionidinfo_t *sessionid) {
    return (remove_sessionid(sessionidstatsmem, sessionid));
}

static ngx_int_t loc_insert_update_sessionid(sessionidinfo_t *sessionid) {
    return (insert_update_sessionid(sessionidstatsmem, sessionid));
}

const struct sessionid_storage_method sessionid_storage = {
    loc_read_sessionid,
    loc_get_ids_used_sessionid,
    loc_get_max_size_sessionid,
    loc_remove_sessionid,
    loc_insert_update_sessionid
};

const struct sessionid_storage_method *get_sessionid_storage() {
    return &sessionid_storage;
}

static void cleanup_manager(void *param) {
    /* shared memory */
    contextstatsmem = NULL;
    nodestatsmem = NULL;
    hoststatsmem = NULL;
    balancerstatsmem = NULL;
    sessionidstatsmem = NULL;
    domainstatsmem = NULL;
    jgroupsidstatsmem = NULL;

}

static int count_sessionid(ngx_http_request_t *r, u_char *route) {
    int size, i;
    int *id;
    int count = 0;

    /* Count the sessionid corresponding to the route */
    size = loc_get_max_size_sessionid();
    if (size == 0)
        return 0;
    id = ngx_palloc(r->pool, sizeof (int) * size);
    size = get_ids_used_sessionid(sessionidstatsmem, id);
    for (i = 0; i < size; i++) {
        sessionidinfo_t *ou;
        if (get_sessionid(sessionidstatsmem, &ou, id[i]) != NGX_OK)
            continue;
        if (ngx_strcmp(route, ou->JVMRoute) == 0)
            count++;
    }
    return count;
}

static u_char *node_string(ngx_http_request_t *r, u_char *JVMRoute) {
    u_char *raw = ngx_pstrcat(r->pool, "JVMRoute=", JVMRoute, NULL);
    return raw;
}

static u_char *context_string(ngx_http_request_t *r, contextinfo_t *ou, u_char *Alias, u_char *JVMRoute) {
    u_char context[sizeof (ou->context) + 1];
    u_char *raw;
    context[sizeof (ou->context)] = '\0';
    strncpy((char *) context, ou->context, sizeof (ou->context));
    raw = ngx_pstrcat(r->pool, "JVMRoute=", JVMRoute, "&Alias=", Alias, "&Context=", context, NULL);
    return raw;
}

static void node_command_string(ngx_http_request_t *r, u_char *JVMRoute, ngx_buf_t *b) {
    ngx_bprintf(b, "<a href=\"%V?%sCmd=ENABLE-APP&Range=NODE&%s\">Enable Contexts</a> ",
            &r->uri, balancer_nonce_string(r), node_string(r, JVMRoute));
    ngx_bprintf(b, "<a href=\"%V?%sCmd=DISABLE-APP&Range=NODE&%s\">Disable Contexts</a> ",
            &r->uri, balancer_nonce_string(r), node_string(r, JVMRoute));
    ngx_bprintf(b, "<a href=\"%V?%sCmd=STOP-APP&Range=NODE&%s\">Stop Contexts</a>",
            &r->uri, balancer_nonce_string(r), node_string(r, JVMRoute));
}

static void domain_command_string(ngx_http_request_t *r, u_char *Domain, ngx_buf_t *b) {
    ngx_bprintf(b, "<a href=\"%V?%sCmd=ENABLE-APP&Range=DOMAIN&Domain=%s\">Enable Nodes</a> ",
            &r->uri, balancer_nonce_string(r), Domain);
    ngx_bprintf(b, "<a href=\"%V?%sCmd=DISABLE-APP&Range=DOMAIN&Domain=%s\">Disable Nodes</a> ",
            &r->uri, balancer_nonce_string(r), Domain);
    ngx_bprintf(b, "<a href=\"%V?%sCmd=STOP-APP&Range=DOMAIN&Domain=%s\">Stop Nodes</a>",
            &r->uri, balancer_nonce_string(r), Domain);
}

static void context_command_string(ngx_http_request_t *r, contextinfo_t *ou, u_char *Alias, u_char *JVMRoute, ngx_buf_t *b) {
    if (ou->status == DISABLED) {
        ngx_bprintf(b, "<a href=\"%V?%sCmd=ENABLE-APP&Range=CONTEXT&%s\">Enable</a> ",
                &r->uri, balancer_nonce_string(r), context_string(r, ou, Alias, JVMRoute));
        ngx_bprintf(b, " <a href=\"%V?%sCmd=STOP-APP&Range=CONTEXT&%s\">Stop</a>",
                &r->uri, balancer_nonce_string(r), context_string(r, ou, Alias, JVMRoute));
    }
    if (ou->status == ENABLED) {
        ngx_bprintf(b, "<a href=\"%V?%sCmd=DISABLE-APP&Range=CONTEXT&%s\">Disable</a>",
                &r->uri, balancer_nonce_string(r), context_string(r, ou, Alias, JVMRoute));
        ngx_bprintf(b, " <a href=\"%V?%sCmd=STOP-APP&Range=CONTEXT&%s\">Stop</a>",
                &r->uri, balancer_nonce_string(r), context_string(r, ou, Alias, JVMRoute));
    }
    if (ou->status == STOPPED) {
        ngx_bprintf(b, "<a href=\"%V?%sCmd=ENABLE-APP&Range=CONTEXT&%s\">Enable</a> ",
                &r->uri, balancer_nonce_string(r), context_string(r, ou, Alias, JVMRoute));
        ngx_bprintf(b, "<a href=\"%V?%sCmd=DISABLE-APP&Range=CONTEXT&%s\">Disable</a>",
                &r->uri, balancer_nonce_string(r), context_string(r, ou, Alias, JVMRoute));
    }
}

static void manager_sessionid(ngx_http_request_t *r, ngx_buf_t *b) {
    int size, i;
    int *id;

    /* Process the Sessionids */
    size = loc_get_max_size_sessionid();
    if (size == 0)
        return;
    id = ngx_palloc(r->pool, sizeof (int) * size);
    size = get_ids_used_sessionid(sessionidstatsmem, id);
    if (!size)
        return;
    ngx_bprintf(b, "<h1>SessionIDs:</h1>");
    ngx_bprintf(b, "<pre>");
    for (i = 0; i < size; i++) {
        sessionidinfo_t *ou;
        if (get_sessionid(sessionidstatsmem, &ou, id[i]) != NGX_OK)
            continue;
        ngx_bprintf(b, "id: %*s route: %*s\n", (int) sizeof (ou->sessionid), ou->sessionid, (int) sizeof (ou->JVMRoute), ou->JVMRoute);
    }
    ngx_bprintf(b, "</pre>");

}

static void manager_info_contexts(ngx_http_request_t *r, int reduce_display, int allow_cmd, int node, int host, u_char *Alias, u_char *JVMRoute, ngx_buf_t *b) {
    int size, i;
    int *id;
    /* Process the Contexts */
    if (!reduce_display)
        ngx_bprintf(b, "<h3>Contexts:</h3>");
    ngx_bprintf(b, "<pre>");
    size = loc_get_max_size_context();
    if (size == 0)
        return;
    id = ngx_palloc(r->pool, sizeof (int) * size);
    size = get_ids_used_context(contextstatsmem, id);
    for (i = 0; i < size; i++) {
        contextinfo_t *ou;
        char *status;
        if (get_context(contextstatsmem, &ou, id[i]) != NGX_OK)
            continue;
        if (ou->node != node || ou->vhost != host)
            continue;
        status = "REMOVED";
        switch (ou->status) {
            case ENABLED:
                status = "ENABLED";
                break;
            case DISABLED:
                status = "DISABLED";
                break;
            case STOPPED:
                status = "STOPPED";
                break;
        }
        ngx_bprintf(b, "%*s, Status: %s Request: %d ", ngx_strlen(ou->context), ou->context, status, ou->nbrequests);
        if (allow_cmd)
            context_command_string(r, ou, Alias, JVMRoute, b);
        ngx_bprintf(b, "\n");
    }
    ngx_bprintf(b, "</pre>");
}

static void manager_info_hosts(ngx_http_request_t *r, int reduce_display, int allow_cmd, int node, u_char *JVMRoute, ngx_buf_t *b) {
    int size, i, j;
    int *id, *idChecker;
    int vhost = 0;

    /* Process the Vhosts */
    size = loc_get_max_size_host();
    if (size == 0)
        return;
    id = ngx_palloc(r->pool, sizeof (int) * size);
    size = get_ids_used_host(hoststatsmem, id);
    idChecker = ngx_pcalloc(r->pool, sizeof (int) * size);
    for (i = 0; i < size; i++) {
        hostinfo_t *ou;
        if (get_host(hoststatsmem, &ou, id[i]) != NGX_OK)
            continue;
        if (ou->node != node)
            continue;
        if (ou->vhost != vhost) {
            /* if we've logged this already, contine */
            if (idChecker[i] == 1)
                continue;
            if (vhost && !reduce_display)
                ngx_bprintf(b, "</pre>");
            if (!reduce_display)
                ngx_bprintf(b, "<h2> Virtual Host %d:</h2>", ou->vhost);
            manager_info_contexts(r, reduce_display, allow_cmd, ou->node, ou->vhost, ou->host, JVMRoute, b);
            if (reduce_display)
                ngx_bprintf(b, "Aliases: ");
            else {
                ngx_bprintf(b, "<h3>Aliases:</h3>");
                ngx_bprintf(b, "<pre>");
            }
            vhost = ou->vhost;

            if (reduce_display)
                ngx_bprintf(b, "%*s ", ngx_strlen(ou->host), ou->host);
            else
                ngx_bprintf(b, "%*s\n", ngx_strlen(ou->host), ou->host);

            /* Go ahead and check for any other later alias entries for this vhost and print them now */
            for (j = i + 1; j < size; j++) {
                hostinfo_t *pv;
                if (get_host(hoststatsmem, &pv, id[j]) != NGX_OK)
                    continue;
                if (pv->node != node)
                    continue;
                if (pv->vhost != vhost)
                    continue;

                /* mark this entry as logged */
                idChecker[j] = 1;
                /* step the outer loop forward if we can */
                if (i == j - 1)
                    i++;
                if (reduce_display)
                    ngx_bprintf(b, "%*s ", ngx_strlen(pv->host), pv->host);
                else
                    ngx_bprintf(b, "%*s\n", ngx_strlen(pv->host), pv->host);
            }
        }
    }
    if (size && !reduce_display)
        ngx_bprintf(b, "</pre>");

}

/*
 * Insert the hosts from Alias information
 */
static ngx_int_t insert_update_hosts(mem_t *mem, u_char *str, int node, int vhost) {
    u_char *ptr = str;
    u_char *previous = str;
    hostinfo_t info;
    u_char empty[1] = {'\0'};
    ngx_int_t status;

    info.node = node;
    info.vhost = vhost;
    if (ptr == NULL) {
        ptr = empty;
        previous = ptr;
    }
    while (*ptr) {
        if (*ptr == ',') {
            *ptr = '\0';
            ngx_memcpy(info.host, previous, sizeof (info.host));
            status = insert_update_host(mem, &info);
            if (status != NGX_OK)
                return status;
            previous = ptr + 1;
        }
        ptr++;
    }
    ngx_memcpy(info.host, previous, sizeof (info.host));
    return insert_update_host(mem, &info);
}

/*
 * Insert the context from Context information
 * Note:
 * 1 - if status is REMOVE remove_context will be called.
 * 2 - return codes of REMOVE are ignored (always success).
 *
 */
static ngx_int_t insert_update_contexts(mem_t *mem, u_char *str, int node, int vhost, int status) {
    u_char *ptr = str;
    u_char *previous = str;
    ngx_int_t ret = NGX_OK;
    contextinfo_t info;
    u_char empty[2] = {'/', '\0'};

    info.node = node;
    info.vhost = vhost;
    info.status = status;
    if (ptr == NULL) {
        ptr = empty;
        previous = ptr;
    }
    while (*ptr) {
        if (*ptr == ',') {
            *ptr = '\0';
            info.id = 0;
            ngx_memcpy(info.context, previous, sizeof (info.context));
            if (status != REMOVE) {
                ret = insert_update_context(mem, &info);
                if (ret != NGX_OK)
                    return ret;
            } else
                remove_context(mem, &info);

            previous = ptr + 1;
        }
        ptr++;
    }
    info.id = 0;
    ngx_memcpy(info.context, previous, sizeof (info.context));
    if (status != REMOVE)
        ret = insert_update_context(mem, &info);
    else
        remove_context(mem, &info);
    return ret;
}

/*
 * Process Functions, do the job
 */

/* Process a *-APP command that applies to the node */
static u_char *process_node_cmd(ngx_http_request_t *r, int status, int *errtype, nodeinfo_t *node) {
    /* for read the hosts */
    int i, j;
    int size = loc_get_max_size_host();
    int *id;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "process_node_cmd %d processing node: %d", status, node->mess.id);
    if (size == 0)
        goto done;
    id = ngx_palloc(r->pool, sizeof (int) * size);
    size = get_ids_used_host(hoststatsmem, id);
    for (i = 0; i < size; i++) {
        hostinfo_t *ou;
        int sizecontext;
        int *idcontext;

        if (get_host(hoststatsmem, &ou, id[i]) != NGX_OK)
            continue;
        if (ou->node != node->mess.id)
            continue;
        /* If the host corresponds to a node process all contextes */
        sizecontext = get_max_size_context(contextstatsmem);
        idcontext = ngx_palloc(r->pool, sizeof (int) * sizecontext);
        sizecontext = get_ids_used_context(contextstatsmem, idcontext);
        for (j = 0; j < sizecontext; j++) {
            contextinfo_t *context;
            if (get_context(contextstatsmem, &context, idcontext[j]) != NGX_OK)
                continue;
            if (context->vhost == ou->vhost &&
                    context->node == ou->node) {
                /* Process the context */
                if (status != REMOVE) {
                    context->status = status;
                    insert_update_context(contextstatsmem, context);
                } else
                    remove_context(contextstatsmem, context);

            }
        }
        if (status == REMOVE) {
            remove_host(hoststatsmem, ou);
        }
    }

    /* The REMOVE-APP * removes the node (well mark it removed) */
    if (status == REMOVE) {
        int id;
        node->mess.remove = 1;
        insert_update_node(nodestatsmem, node, &id);
    }

done:

    *errtype = ngx_http_send_buffer(r, NULL, NGX_HTTP_OK);
    return NULL;

}

/* Check that the method is one of ours */
static int check_method(ngx_http_request_t *r) {
    int ours = 0;
    if (ngx_strncasecmp(r->method_name.data, (u_char *) "CONFIG", r->method_name.len) == 0)
        ours = 1;
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "ENABLE-APP", r->method_name.len) == 0)
        ours = 1;
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "DISABLE-APP", r->method_name.len) == 0)
        ours = 1;
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "STOP-APP", r->method_name.len) == 0)
        ours = 1;
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "REMOVE-APP", r->method_name.len) == 0)
        ours = 1;
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "STATUS", r->method_name.len) == 0)
        ours = 1;
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "DUMP", r->method_name.len) == 0)
        ours = 1;
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "ERROR", r->method_name.len) == 0)
        ours = 1;
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "INFO", r->method_name.len) == 0)
        ours = 1;
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "PING", r->method_name.len) == 0)
        ours = 1;
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "ADDID", r->method_name.len) == 0)
        ours = 1;
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "REMOVEID", r->method_name.len) == 0)
        ours = 1;
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "QUERY", r->method_name.len) == 0)
        ours = 1;
    return ours;
}

/* already called in the knowledge that the characters are hex digits */

/* Copied from modules/proxy/proxy_util.c */
static int mod_manager_hex2c(const u_char *x) {
    int i, ch;

    ch = x[0];
    if (isdigit(ch)) {
        i = ch - '0';
    } else if (isupper(ch)) {
        i = ch - ('A' - 10);
    } else {
        i = ch - ('a' - 10);
    }
    i <<= 4;

    ch = x[1];
    if (isdigit(ch)) {
        i += ch - '0';
    } else if (isupper(ch)) {
        i += ch - ('A' - 10);
    } else {
        i += ch - ('a' - 10);
    }
    return i;
}

static int decodeenc(u_char *x) {
    int i, j, ch;

    if (x[0] == '\0')
        return 0; /* special case for no characters */
    for (i = 0, j = 0; x[i] != '\0'; i++, j++) {
        /* decode it if not already done */
        ch = x[i];
        if (ch == '%' && isxdigit(x[i + 1]) && isxdigit(x[i + 2])) {
            ch = mod_manager_hex2c(&x[i + 1]);
            i += 2;
        }
        x[j] = ch;
    }
    x[j] = '\0';
    return j;
}

/*
 * Check that the node could be handle as is there were the same.
 */
static int is_same_node(nodeinfo_t *nodeinfo, nodeinfo_t *node) {
    if (ngx_strcmp(nodeinfo->mess.balancer, node->mess.balancer))
        return 0;
    if (ngx_strcmp(nodeinfo->mess.Host, node->mess.Host))
        return 0;
    if (ngx_strcmp(nodeinfo->mess.Port, node->mess.Port))
        return 0;
    if (ngx_strcmp(nodeinfo->mess.Type, node->mess.Type))
        return 0;
    if (nodeinfo->mess.reversed != node->mess.reversed)
        return 0;

    /* Those means the reslist has to be changed */
    if (nodeinfo->mess.smax != node->mess.smax)
        return 0;
    if (nodeinfo->mess.ttl != node->mess.ttl)
        return 0;

    /* All other fields can be modified without causing problems */
    return -1;
}

void ngx_http_health_send_request(ngx_connection_t *c) {
    ssize_t size;
    ssize_t send_pos = 0;
    ngx_http_upstream_health_status_t *response_status = c->data;

    do {
        size = c->send(c, response_status->request_data.data + send_pos, response_status->request_data.len - send_pos);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "healthcheck: Send size %z", size);
        if (size == NGX_ERROR || size == 0) {
            // If the send fails, the connection is bad. Close it out
            ngx_close_connection(c);
            c = NULL;
            response_status->response_code = size;
            response_status->response_time = ngx_get_milli_time() - response_status->response_time;
            break;
        } else if (size == NGX_AGAIN) {
            // I guess this means return and try again later
            break;
        } else {
            send_pos += size;
        }
    } while (send_pos < (ssize_t) response_status->request_data.len);

    if (send_pos > (ssize_t) response_status->request_data.len) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0, "healthcheck: Logic error. %z send pos bigger than buffer len %i", send_pos, response_status->request_data.len);
    } else if (send_pos == (ssize_t) response_status->request_data.len) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "healthcheck: Finished sending request");
    }
    
    
}

void ngx_http_health_write_handler(ngx_event_t *wev) {
    ngx_connection_t *c;

    c = wev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0,
            "healthcheck: Write handler called");

    ngx_http_health_send_request(c);
}

void ngx_http_health_read_handler(ngx_event_t *rev) {
    ngx_connection_t *c;
    ssize_t size;
    ngx_buf_t *rb;
    //    ngx_int_t rc;    
    ngx_http_upstream_health_status_t *response_status;
    // ngx_int_t expect_finished;

    c = rev->data;
    response_status = c->data;

    rb = &response_status->response_buffer;

    do {
        size = c->recv(c, rb->pos, rb->end - rb->pos);
        ngx_log_debug2(NGX_LOG_DEBUG, rev->log, 0, "health: Recv size %z when I wanted %O", size, rb->end - rb->pos);
        if (size == NGX_ERROR) {
            response_status->response_code = size;
            break;
        } else if (size == NGX_AGAIN) {
            break;
        } else if (size == 0) {
        //    expect_finished = 1;
            break;
        } else {
            rb->pos += size;
        }
    } while (rb->pos < rb->end);

    if (rb->pos != rb->start) {
        if (!ngx_strncmp("HTTP", rb->start, 4)) {
            response_status->response_code = ngx_atoi(rb->start + 9, 3);
        } else {
            response_status->response_code = NGX_NONE;
        }
    }

    response_status->response_time = ngx_get_milli_time() - response_status->response_time;

    ngx_close_connection(c);
    c = NULL;
}

static ngx_int_t ngx_http_health_connect(ngx_http_request_t *r, struct sockaddr *sockaddr, socklen_t socklen, ngx_str_t *name, void *data) {

    ngx_int_t rc = NGX_ERROR;
    ngx_peer_connection_t *pc;
    ngx_connection_t *c;

    ngx_http_upstream_health_status_t *response_status = data;
    
    pc = ngx_palloc(r->pool, sizeof (ngx_peer_connection_t));

    if (!pc)
        return NGX_ERROR;

    ngx_memzero(pc, sizeof (ngx_peer_connection_t));

    pc->get = ngx_event_get_peer;


    pc->sockaddr = sockaddr;
    pc->socklen = socklen;
    pc->name = name;

    pc->log = r->connection->log;
    pc->log_error = NGX_ERROR_ERR;

    pc->cached = 0;
    pc->connection = NULL;

    response_status->response_code = NGX_ERROR;
    response_status->response_time = ngx_get_milli_time();
    rc = ngx_event_connect_peer(pc);
    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0, "health: Could not connect to peer: %i", rc);
        if (pc->connection) {
            ngx_close_connection(pc->connection);
        }
        response_status->response_time = ngx_get_milli_time() - response_status->response_time;
        response_status->response_code = rc;
        return NGX_ERROR;
    }

    c = pc->connection;
    c->data = data;
    c->log = pc->log;
    c->write->handler = ngx_http_health_write_handler;
    c->read->handler = ngx_http_health_read_handler;
    c->sendfile = 0;
    c->read->log = c->log;
    c->write->log = c->log;

    ngx_http_health_send_request(c);

    return NGX_OK;
}
static int loc_get_max_size_context();
static int loc_get_ids_used_context(int *ids);
static ngx_int_t loc_read_context(int ids, contextinfo_t **context);

static int isnode_up(ngx_http_request_t *r, int id, int load) {
    nodeinfo_t *node;
    ngx_int_t rc;

    if (loc_read_node(id, &node) != NGX_OK)
        return NGX_ERROR;

    if ((load >= 0 || load == -2)) {
        ngx_url_t u;

        u.url.data = node->mess.Host;
        u.url.len = ngx_strlen(node->mess.Host);

        u.default_port = ngx_atoi(node->mess.Port, ngx_strlen(node->mess.Port));

        if (ngx_parse_url(r->pool, &u) != NGX_OK) {
            if (u.err) {
                ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "%s in isnode \"%V\"", u.err, &u.url);
            }
            return NGX_ERROR;
        }

        if (u.naddrs > 0) {
            ngx_http_upstream_health_status_t *response_status;
            ngx_int_t addrs_idx = u.naddrs - 1;
            response_status = get_node_upstream_status(node);
            rc = ngx_http_health_connect(r, u.addrs[addrs_idx].sockaddr, u.addrs[addrs_idx].socklen, &u.addrs[addrs_idx].name, response_status);
            if (rc == NGX_OK) {
                int i;
                int size;
                mod_manager_config *mconf = ngx_http_get_module_srv_conf(r, ngx_http_manager_module);
                size = loc_get_max_size_context();
                if (size != 0) {
                    int *contexts = ngx_palloc(r->pool, sizeof (int) * size);
                    int sizecontext = loc_get_ids_used_context(contexts);
                    for (i = 0; i < sizecontext; i++) {
                        contextinfo_t* h;
                        int context_index = contexts[i];
                        ngx_uint_t context_proxy_idx = 0;
                        ngx_http_proxy_loc_conf_t  *plcf = NULL;
                        loc_read_context(context_index, &h);
                        if (!h)
                            continue;
                        context_proxy_idx = hash ((u_char *)h->context) % DEFMAXCONTEXT;
                        plcf = mconf->plcf[context_proxy_idx];
                        ngx_http_upstream_srv_conf_t *uscf = plcf->upstream.upstream;
                        ngx_http_upstream_fair_peers_t *peers = uscf->peer.data;
                        ngx_uint_t i;
                        for (i = 0; i < peers->number; i++) {
                            if (!ngx_memcmp(peers->peer[i].sockaddr, u.addrs[addrs_idx].sockaddr, peers->peer[i].socklen)) {
                                peers->peer[i].weight = load;
                            }
                        }
                    }
                }
            }
        } else
            rc = NGX_ERROR;

        if (rc != NGX_OK)
            return rc;

    }

    if (load == -2) {
        return NGX_OK;
    }


    return (NGX_OK);
}

/*
 * Call the ping/pong logic using scheme://host:port
 * Do a ping/png request to the node and set the load factor.
 */
static int ishost_up(ngx_http_request_t *r, u_char *scheme, u_char *host, u_char *port) {
     ngx_url_t u;
     ngx_int_t rc;
     nodeinfo_t *node, nodeinfo;
     
    u.url.data = host;
    u.url.len = ngx_strlen(host);

    u.default_port = ngx_atoi(port, ngx_strlen(port));

    if (ngx_parse_url(r->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "%s in isnode \"%V\"", u.err, &u.url);
        }
        return NGX_ERROR;
    }

    if (u.naddrs > 0) {
        ngx_http_upstream_health_status_t *response_status = NULL;
        ngx_int_t addrs_idx = u.naddrs - 1;
        ngx_memcpy (nodeinfo.mess.Host, host, ngx_strlen(host));
        node = read_node(nodestatsmem, &nodeinfo);
        if (node)
            response_status = get_node_upstream_status(node);
        rc = ngx_http_health_connect(r, u.addrs[addrs_idx].sockaddr, u.addrs[addrs_idx].socklen, &u.addrs[addrs_idx].name, response_status);
    } else
        rc = NGX_ERROR;

    if (rc != NGX_OK)
        return rc;
    
    return NGX_OK;
}

static u_char **process_buff(ngx_http_request_t *r, u_char *buff) {
    int i = 0;
    u_char *s = buff;
    u_char **ptr = NULL;
    for (; *s != '\0'; s++) {
        if (*s == '&' || *s == '=') {
            i++;
        }
    }
    ptr = ngx_palloc(r->pool, sizeof (char *) * (i + 2));
    if (ptr == NULL)
        return NULL;

    s = buff;
    ptr[0] = s;
    ptr[i + 1] = NULL;
    i = 1;
    for (; *s != '\0'; s++) {
        if (*s == '&' || *s == '=') {
            *s = '\0';
            ptr[i] = s + 1;
            i++;
        }
        if (*s == ' ')
            *s = '\0';
    }
    return ptr;
}

/* Process an enable/disable/stop/remove application message */
static u_char *process_appl_cmd(ngx_http_request_t *r, u_char **ptr, int status, int *errtype, int global, int fromnode) {
    nodeinfo_t nodeinfo;
    nodeinfo_t *node;
    struct cluster_host *vhost;

    int i = 0;
    hostinfo_t hostinfo;
    hostinfo_t *host;

    memset(&nodeinfo.mess, '\0', sizeof (nodeinfo.mess));
    /* Map nothing by default */
    vhost = ngx_palloc(r->pool, sizeof (struct cluster_host));
    vhost->host = NULL;
    vhost->context = NULL;
    vhost->next = NULL;

    while (ptr[i]) {
        if (ngx_strcasecmp(ptr[i], (u_char *) "JVMRoute") == 0) {
            if (ngx_strlen(ptr[i + 1]) >= sizeof (nodeinfo.mess.JVMRoute)) {
                *errtype = TYPESYNTAX;
                return (u_char *) SROUBIG;
            }
            strcpy((char *) nodeinfo.mess.JVMRoute, (char *) ptr[i + 1]);
            nodeinfo.mess.id = 0;
        }
        if (ngx_strcasecmp(ptr[i], (u_char *) "Alias") == 0) {
            if (vhost->host) {
                *errtype = TYPESYNTAX;
                return (u_char *) SMULALB;
            }
            vhost->host = ptr[i + 1];
        }
        if (ngx_strcasecmp(ptr[i], (u_char *) "Context") == 0) {
            if (vhost->context) {
                *errtype = TYPESYNTAX;
                return (u_char *) SMULCTB;
            }
            vhost->context = ptr[i + 1];
        }
        i++;
        i++;
    }


    /* Check for JVMRoute, Alias and Context */
    if (nodeinfo.mess.JVMRoute[0] == '\0') {
        *errtype = TYPESYNTAX;
        return (u_char *) SROUBAD;
    }
    if (vhost->context == NULL && vhost->host != NULL) {
        *errtype = TYPESYNTAX;
        return (u_char *) SALIBAD;
    }
    if (vhost->host == NULL && vhost->context != NULL) {
        *errtype = TYPESYNTAX;
        return (u_char *) SCONBAD;
    }

    /* Read the node */
    node = read_node(nodestatsmem, &nodeinfo);
    if (node == NULL) {
        if (status == REMOVE)
            goto done; /* Already done */
        *errtype = TYPEMEM;
        return (u_char *) MNODERD;
    }

    /* If the node is marked removed check what to do */
    if (node->mess.remove) {
        if (status == REMOVE)
            goto done; /* Already done */
        else {
            /* Act has if the node wasn't found */
            *errtype = TYPEMEM;
            return (u_char *) MNODERD;
        }
    }

    /* Process the * APP commands */
    if (global) {
        return (process_node_cmd(r, status, errtype, node));
    }

    /* Read the ID of the virtual host corresponding to the first Alias */
    hostinfo.node = node->mess.id;
    if (vhost->host != NULL) {
        u_char *s = hostinfo.host;
        unsigned int j = 1;
        ngx_memcpy(hostinfo.host, vhost->host, sizeof (hostinfo.host));
        unsigned int h = ngx_strlen(hostinfo.host) + 1;
        while (*s != ',' && j < h) {
            j++;
            s++;
        }
        *s = '\0';
    } else
        hostinfo.host[0] = '\0';

    hostinfo.id = 0;
    host = read_host(hoststatsmem, &hostinfo);
    if (host == NULL) {
        /* If REMOVE ignores it */
        if (status == REMOVE)
            goto done;
        else {
            int vid, size, *id;
            /* Find the first available vhost id */
            vid = 0;
            size = loc_get_max_size_host();
            id = ngx_palloc(r->pool, sizeof (int) * size);
            size = get_ids_used_host(hoststatsmem, id);
            for (i = 0; i < size; i++) {
                hostinfo_t *ou;
                if (get_host(hoststatsmem, &ou, id[i]) != NGX_OK)
                    continue;

                if (ou->node == node->mess.id && ou->vhost > vid)
                    vid = ou->vhost;
            }
            vid++; /* Use next one. */
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "process_appl_cmd: adding vhost: %d node: %d",
                    vid, node->mess.id);

            /* If the Host doesn't exist yet create it */
            if (insert_update_hosts(hoststatsmem, vhost->host, node->mess.id, vid) != NGX_OK) {
                *errtype = TYPEMEM;
                return (u_char *) MHOSTUI;
            }
            hostinfo.id = 0;
            hostinfo.node = node->mess.id;
            if (vhost->host != NULL)
                ngx_memcpy(hostinfo.host, vhost->host, sizeof (hostinfo.host));
            else
                hostinfo.host[0] = '\0';
            host = read_host(hoststatsmem, &hostinfo);
            if (host == NULL) {
                *errtype = TYPEMEM;
                return (u_char *) MHOSTRD;
            }
        }
    }

    if (status == ENABLED) {
        /* There is no load balancing between balancers */
        int size = loc_get_max_size_context();
        int *id = ngx_palloc(r->pool, sizeof (int) * size);
        size = get_ids_used_context(contextstatsmem, id);
        for (i = 0; i < size; i++) {
            contextinfo_t *ou;
            if (get_context(contextstatsmem, &ou, id[i]) != NGX_OK)
                continue;
            if (ngx_strcmp(ou->context, vhost->context) == 0) {
                /* There is the same context somewhere else */
                nodeinfo_t *hisnode;
                if (get_node(nodestatsmem, &hisnode, ou->node) != NGX_OK)
                    continue;
                if (ngx_strcmp(hisnode->mess.balancer, node->mess.balancer)) {
                    /* the same context would be on 2 different balancer */
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                            "ENABLE: context %s is in balancer %s and %s", vhost->context,
                            node->mess.balancer, hisnode->mess.balancer);
                }
            }
        }
    }

    /* Now update each context from Context: part */
    if (insert_update_contexts(contextstatsmem, vhost->context, node->mess.id, host->vhost, status) != NGX_OK) {
        *errtype = TYPEMEM;
        return (u_char *) MCONTUI;
    }

    /* Remove the host if all the contextes have been removed */
    if (status == REMOVE) {
        int size = loc_get_max_size_context();
        int *id = ngx_palloc(r->pool, sizeof (int) * size);
        size = get_ids_used_context(contextstatsmem, id);
        for (i = 0; i < size; i++) {
            contextinfo_t *ou;
            if (get_context(contextstatsmem, &ou, id[i]) != NGX_OK)
                continue;
            if (ou->vhost == host->vhost &&
                    ou->node == node->mess.id)
                break;
        }
        if (i == size) {
            int size = loc_get_max_size_host();
            int *id = ngx_palloc(r->pool, sizeof (int) * size);
            size = get_ids_used_host(hoststatsmem, id);
            for (i = 0; i < size; i++) {
                hostinfo_t *ou;

                if (get_host(hoststatsmem, &ou, id[i]) != NGX_OK)
                    continue;
                if (ou->vhost == host->vhost && ou->node == node->mess.id)
                    remove_host(hoststatsmem, ou);
            }
        }
    } else if (status == STOPPED) {
        /* insert_update_contexts in fact makes that vhost->context corresponds only to the first context... */
        contextinfo_t in;
        contextinfo_t *ou;
        in.id = 0;
        ngx_memcpy(in.context, vhost->context, sizeof (in.context));
        in.vhost = host->vhost;
        in.node = node->mess.id;
        ou = read_context(contextstatsmem, &in);
        if (ou != NULL) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "process_appl_cmd: STOP-APP nbrequests %d", ou->nbrequests);
            if (fromnode) {
                ngx_str_t ct = ngx_string("text/plain");
                ngx_str_t *ctp = &ct;
                r->headers_out.content_type_len = ct.len;
                r->headers_out.content_type = *ctp;
                ngx_buf_t *b = ngx_create_temp_buf(r->pool, 1024 * 2);
                ngx_bprintf(b, "Type=STOP-APP-RSP&JvmRoute=%*s&Alias=%*s&Context=%*s&Requests=%d",
                        ngx_strlen(nodeinfo.mess.JVMRoute), nodeinfo.mess.JVMRoute,
                        ngx_strlen(vhost->host), vhost->host,
                        ngx_strlen(vhost->context), vhost->context,
                        ou->nbrequests);
                ngx_bprintf(b, "\n");

                *errtype = ngx_http_send_buffer(r, b, NGX_HTTP_OK);
            }
        } else {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "process_appl_cmd: STOP-APP can't read_context");
        }
    }

done:
    *errtype = ngx_http_send_buffer(r, NULL, NGX_HTTP_OK);
    return NULL;
}

static u_char *process_enable(ngx_http_request_t *r, u_char **ptr, int *errtype, int global) {
    return process_appl_cmd(r, ptr, ENABLED, errtype, global, 0);
}

static u_char *process_disable(ngx_http_request_t *r, u_char **ptr, int *errtype, int global) {
    return process_appl_cmd(r, ptr, DISABLED, errtype, global, 0);
}

static u_char *process_stop(ngx_http_request_t *r, u_char **ptr, int *errtype, int global, int fromnode) {
    return process_appl_cmd(r, ptr, STOPPED, errtype, global, fromnode);
}

static u_char *process_remove(ngx_http_request_t *r, u_char **ptr, int *errtype, int global) {
    return process_appl_cmd(r, ptr, REMOVE, errtype, global, 0);
}

static u_char *process_domain(ngx_http_request_t *r, u_char **ptr, int *errtype, const u_char *cmd, const u_char *domain) {
    int size, i;
    int *id;
    u_char *errstring = NULL;
    int pos;
    ngx_str_t jvm_route = ngx_string("JVMRoute");
    size = loc_get_max_size_node();
    if (size == 0)
        return NULL;
    id = ngx_palloc(r->pool, sizeof (int) * size);
    size = get_ids_used_node(nodestatsmem, id);

    for (pos = 0; ptr[pos] != NULL && ptr[pos + 1] != NULL; pos = pos + 2);

    ptr[pos] = ngx_pstrdup2(r->pool, &jvm_route);
    ptr[pos + 2] = NULL;
    ptr[pos + 3] = NULL;

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "process_domain");

    for (i = 0; i < size; i++) {
        nodeinfo_t *ou;
        if (get_node(nodestatsmem, &ou, id[i]) != NGX_OK)
            continue;
        if (ngx_strcmp(ou->mess.Domain, domain) != 0)
            continue;
        /* add the JVMRoute */
        ngx_str_t jvm_route_value;
        jvm_route_value.data = ou->mess.JVMRoute;
        jvm_route_value.len = ngx_strlen(ou->mess.JVMRoute);
        ptr[pos + 1] = ngx_pstrdup2(r->pool, &jvm_route_value);
        u_char *pcmd = (u_char *) cmd;

        if (ngx_strcasecmp(pcmd, (u_char *) "ENABLE-APP") == 0)
            errstring = process_enable(r, ptr, errtype, RANGENODE);
        else if (ngx_strcasecmp(pcmd, (u_char *) "DISABLE-APP") == 0)
            errstring = process_disable(r, ptr, errtype, RANGENODE);
        else if (ngx_strcasecmp(pcmd, (u_char *) "STOP-APP") == 0)
            errstring = process_stop(r, ptr, errtype, RANGENODE, 0);
        else if (ngx_strcasecmp(pcmd, (u_char *) "REMOVE-APP") == 0)
            errstring = process_remove(r, ptr, errtype, RANGENODE);
    }
    return errstring;
}

/*
 * Process the STATUS command
 * Load -1 : Broken
 * Load 0  : Standby.
 * Load 1-100 : Load factor.
 */
static u_char * process_status(ngx_http_request_t *r, u_char **uptr, int *errtype) {
    int Load = -1;
    nodeinfo_t nodeinfo;
    nodeinfo_t *node;
    char **ptr = (char **) uptr;

    int i = 0;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Processing STATUS");
    while (ptr[i]) {
        if (strcasecmp(ptr[i], "JVMRoute") == 0) {
            if (strlen(ptr[i + 1]) >= sizeof (nodeinfo.mess.JVMRoute)) {
                *errtype = TYPESYNTAX;
                return (u_char *) SROUBIG;
            }
            strcpy((char *) nodeinfo.mess.JVMRoute, ptr[i + 1]);
            nodeinfo.mess.id = 0;
        } else if (strcasecmp(ptr[i], "Load") == 0) {
            Load = atoi(ptr[i + 1]);
        } else {
            *errtype = TYPESYNTAX;
            u_char *errstring = ngx_pcalloc(r->pool, sizeof (SBADFLD) + ngx_strlen(ptr[i]) + 1);
            ngx_sprintf(errstring, SBADFLD, ptr[i]);
            return errstring;
        }
        i++;
        i++;
    }

    /* Read the node */
    node = read_node(nodestatsmem, &nodeinfo);
    if (node == NULL) {
        *errtype = TYPEMEM;
        return (u_char *) MNODERD;
    }

    /*
     * If the node is usualable do a ping/pong to prevent Split-Brain Syndrome
     * and update the worker status and load factor acccording to the test result.
     */

    ngx_str_t ct = ngx_string("text/plain");
    ngx_str_t *ctp = &ct;
    r->headers_out.content_type_len = ct.len;
    r->headers_out.content_type = *ctp;

    ngx_buf_t *b = ngx_create_temp_buf(r->pool, 1024 * 2);

    ngx_bprintf(b, "Type=STATUS-RSP&JVMRoute=%*s", ngx_strlen(nodeinfo.mess.JVMRoute), nodeinfo.mess.JVMRoute);

    if (isnode_up(r, node->mess.id, Load) != NGX_OK)
        ngx_bprintf(b, "&State=NOTOK");
    else
        ngx_bprintf(b, "&State=OK");

    ngx_bprintf(b, "&id=%d", random());


    ngx_bprintf(b, "\n");

    *errtype = ngx_http_send_buffer(r, b, NGX_HTTP_OK);

    return NULL;
}

/*
 * Process the PING command
 * With a JVMRoute does a cping/cpong in the node.
 * Without just answers ok.
 * NOTE: It is hard to cping/cpong a host + port but CONFIG + PING + REMOVE_APP *
 *       would do the same.
 */
static u_char *process_ping(ngx_http_request_t *r, u_char **uptr, int *errtype) {
    nodeinfo_t nodeinfo;
    nodeinfo_t *node;
    char *scheme = NULL;
    char *host = NULL;
    char *port = NULL;
    char **ptr = (char **) uptr;
    ngx_buf_t *b;

    int i = 0;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Processing PING");
    nodeinfo.mess.id = -1;
    while (ptr[i] && ptr[i][0] != '\0') {
        if (strcasecmp(ptr[i], "JVMRoute") == 0) {
            if (strlen(ptr[i + 1]) >= sizeof (nodeinfo.mess.JVMRoute)) {
                *errtype = TYPESYNTAX;
                return (u_char *) SROUBIG;
            }
            strcpy((char *) nodeinfo.mess.JVMRoute, ptr[i + 1]);
            nodeinfo.mess.id = 0;
        } else if (strcasecmp(ptr[i], "Scheme") == 0) {
            scheme = ngx_pcalloc(r->pool, strlen(ptr[i + 1]) + 1);
            ngx_memcpy(scheme, ptr[i + 1], strlen(ptr[i + 1]));
        } else if (strcasecmp(ptr[i], "Host") == 0) {
            host = ngx_pcalloc(r->pool, strlen(ptr[i + 1]) + 1);
            ngx_memcpy(scheme, ptr[i + 1], strlen(ptr[i + 1]));
        } else if (strcasecmp(ptr[i], "Port") == 0) {
            port = ngx_pcalloc(r->pool, strlen(ptr[i + 1]) + 1);
            ngx_memcpy(scheme, ptr[i + 1], strlen(ptr[i + 1]));
        } else {
            *errtype = TYPESYNTAX;
            u_char *errstring = ngx_pcalloc(r->pool, sizeof (SBADFLD) + ngx_strlen(ptr[i]) + 1);
            ngx_sprintf(errstring, SBADFLD, ptr[i]);
            return errstring;
        }
        i++;
        i++;
    }

    b = ngx_create_temp_buf(r->pool, 1024 * 2);
    if (nodeinfo.mess.id == -1) {

        /* PING scheme, host, port or just httpd */
        if (scheme == NULL && host == NULL && port == NULL) {
            ngx_str_t ct = ngx_string("text/plain");
            ngx_str_t *ctp = &ct;
            r->headers_out.content_type_len = ct.len;
            r->headers_out.content_type = *ctp;
            ngx_bprintf(b, "Type=PING-RSP&State=OK");
        } else {
            if (scheme == NULL || host == NULL || port == NULL) {
                *errtype = TYPESYNTAX;
                u_char *errstring = ngx_pcalloc(r->pool, sizeof (SMISFLD) + 1);
                ngx_sprintf(errstring, SMISFLD);
                return errstring;
            }
            ngx_str_t ct = ngx_string("text/plain");
            ngx_str_t *ctp = &ct;
            r->headers_out.content_type_len = ct.len;
            r->headers_out.content_type = *ctp;
            ngx_bprintf(b, "Type=PING-RSP");

            if (ishost_up(r, (u_char *) scheme, (u_char *) host, (u_char *) port) != NGX_OK)
                ngx_bprintf(b, "&State=NOTOK");
            else
                ngx_bprintf(b, "&State=OK");
        }
    } else {

        /* Read the node */
        node = read_node(nodestatsmem, &nodeinfo);
        if (node == NULL) {
            *errtype = TYPEMEM;
            return (u_char *) MNODERD;
        }

        /*
         * If the node is usualable do a ping/pong to prevent Split-Brain Syndrome
         * and update the worker status and load factor acccording to the test result.
         */
        ngx_str_t ct = ngx_string("text/plain");
        ngx_str_t *ctp = &ct;
        r->headers_out.content_type_len = ct.len;
        r->headers_out.content_type = *ctp;

        ngx_bprintf(b, "Type=PING-RSP&JVMRoute=%*s", ngx_strlen(nodeinfo.mess.JVMRoute), nodeinfo.mess.JVMRoute);

        if (isnode_up(r, node->mess.id, -2) != NGX_OK)
            ngx_bprintf(b, "&State=NOTOK");
        else
            ngx_bprintf(b, "&State=OK");
    }

    ngx_bprintf(b, "&id=%d", random());


    ngx_bprintf(b, "\n");

    return NULL;
}

/*
 * Process a CONFIG message
 * Balancer: <Balancer name>
 * <balancer configuration>
 * StickySession	StickySessionCookie	StickySessionPath	StickySessionRemove
 * StickySessionForce	Timeout	Maxattempts
 * JvmRoute?: <JvmRoute>
 * Domain: <Domain>
 * <Host: <Node IP>
 * Port: <Connector Port>
 * Type: <Type of the connector>
 * Reserved: <Use connection pool initiated by Tomcat *.>
 * <node conf>
 * flushpackets	flushwait	ping	smax	ttl
 * Virtual hosts in JBossAS
 * Alias: <vhost list>
 * Context corresponding to the applications.
 * Context: <context list>
 */

static u_char *process_config(ngx_http_request_t *r, u_char **uptr, int *errtype) {
    /* Process the node/balancer description */
    nodeinfo_t nodeinfo;
    nodeinfo_t *node;
    balancerinfo_t balancerinfo;
    int mpm_threads = 0;

    char **ptr = (char **) uptr;

    struct cluster_host *vhost;
    struct cluster_host *phost;

    int i = 0;
    int id;
    int vid = 1; /* zero and "" is empty */
    mod_manager_config *mconf = ngx_http_get_module_srv_conf(r, ngx_http_manager_module);

    vhost = ngx_palloc(r->pool, sizeof (struct cluster_host));

    /* Map nothing by default */
    vhost->host = NULL;
    vhost->context = NULL;
    vhost->next = NULL;
    phost = vhost;

    /* Fill default nodes values */
    memset(&nodeinfo.mess, '\0', sizeof (nodeinfo.mess));
    if (mconf->balancername.data != NULL) {
        strcpy((char *) nodeinfo.mess.balancer, (const char *) mconf->balancername.data);
    } else {
        strcpy((char *) nodeinfo.mess.balancer, "mycluster");
    }
    strcpy((char *) nodeinfo.mess.Host, "localhost");
    strcpy((char *) nodeinfo.mess.Port, "8009");
    strcpy((char *) nodeinfo.mess.Type, "ajp");
    nodeinfo.mess.reversed = 0;
    nodeinfo.mess.remove = 0; /* not marked as removed */
    //nodeinfo.mess.flushpackets = flush_off; /* FLUSH_OFF; See enum flush_packets in proxy.h flush_off */
    //nodeinfo.mess.flushwait = PROXY_FLUSH_WAIT;
    nodeinfo.mess.ping = ngx_time_from_sec(10);
    nodeinfo.mess.smax = mpm_threads + 1;
    nodeinfo.mess.ttl = ngx_time_from_sec(60);
    nodeinfo.mess.timeout = 0;
    nodeinfo.mess.id = 0;
    nodeinfo.mess.lastcleantry = 0;

    /* Fill default balancer values */
    memset(&balancerinfo, '\0', sizeof (balancerinfo));
    if (mconf->balancername.data != NULL) {
        strcpy((char *) balancerinfo.balancer, (const char *) mconf->balancername.data);
    } else {
        strcpy((char *) balancerinfo.balancer, "mycluster");
    }
    balancerinfo.StickySession = 1;
    balancerinfo.StickySessionForce = 1;
    strcpy((char *) balancerinfo.StickySessionCookie, "JSESSIONID");
    strcpy((char *) balancerinfo.StickySessionPath, "jsessionid");
    balancerinfo.Maxattempts = 1;
    balancerinfo.Timeout = 0;

    while (ptr[i]) {
        /* XXX: balancer part */
        if (strcasecmp(ptr[i], "Balancer") == 0) {
            if (strlen(ptr[i + 1]) >= sizeof (nodeinfo.mess.balancer)) {
                *errtype = TYPESYNTAX;
                return (u_char *) SBALBIG;
            }
            strcpy((char *) nodeinfo.mess.balancer, ptr[i + 1]);
            strcpy((char *) balancerinfo.balancer, ptr[i + 1]);
        }
        if (strcasecmp(ptr[i], "StickySession") == 0) {
            if (strcasecmp(ptr[i + 1], "no") == 0)
                balancerinfo.StickySession = 0;
        }
        if (strcasecmp(ptr[i], "StickySessionCookie") == 0) {
            if (strlen(ptr[i + 1]) >= sizeof (balancerinfo.StickySessionCookie)) {
                *errtype = TYPESYNTAX;
                return (u_char *) SBAFBIG;
            }
            strcpy((char *) balancerinfo.StickySessionCookie, ptr[i + 1]);
        }
        if (strcasecmp(ptr[i], "StickySessionPath") == 0) {
            if (strlen(ptr[i + 1]) >= sizeof (balancerinfo.StickySessionPath)) {
                *errtype = TYPESYNTAX;
                return (u_char *) SBAFBIG;
            }
            strcpy((char *) balancerinfo.StickySessionPath, ptr[i + 1]);
        }
        if (strcasecmp(ptr[i], "StickySessionRemove") == 0) {
            if (strcasecmp(ptr[i + 1], "yes") == 0)
                balancerinfo.StickySessionRemove = 1;
        }
        if (strcasecmp(ptr[i], "StickySessionForce") == 0) {
            if (strcasecmp(ptr[i + 1], "no") == 0)
                balancerinfo.StickySessionForce = 0;
        }
        /* Note that it is workerTimeout (set/getWorkerTimeout in java code) */
        if (strcasecmp(ptr[i], "WaitWorker") == 0) {
            balancerinfo.Timeout = ngx_time_from_sec(atoi(ptr[i + 1]));
        }
        if (strcasecmp(ptr[i], "Maxattempts") == 0) {
            balancerinfo.Maxattempts = atoi(ptr[i + 1]);
        }

        /* XXX: Node part */
        if (strcasecmp(ptr[i], "JVMRoute") == 0) {
            if (strlen(ptr[i + 1]) >= sizeof (nodeinfo.mess.JVMRoute)) {
                *errtype = TYPESYNTAX;
                return (u_char *) SROUBIG;
            }
            strcpy((char *) nodeinfo.mess.JVMRoute, ptr[i + 1]);
        }
        /* We renamed it LBGroup */
        if (strcasecmp(ptr[i], "Domain") == 0) {
            if (strlen(ptr[i + 1]) >= sizeof (nodeinfo.mess.Domain)) {
                *errtype = TYPESYNTAX;
                return (u_char *) SDOMBIG;
            }
            strcpy((char *) nodeinfo.mess.Domain, ptr[i + 1]);
        }
        if (strcasecmp(ptr[i], "Host") == 0) {
            char *p_read = ptr[i + 1], *p_write = ptr[i + 1];
            int flag = 0;
            if (strlen(ptr[i + 1]) >= sizeof (nodeinfo.mess.Host)) {
                *errtype = TYPESYNTAX;
                return (u_char *) SHOSBIG;
            }

            /* Removes %zone from an address */
            if (*p_read == '[') {
                while (*p_read) {
                    *p_write = *p_read++;
                    if ((*p_write == '%' || flag) && *p_write != ']') {
                        flag = 1;
                    } else {
                        p_write++;
                    }
                }
                *p_write = '\0';
            }

            strcpy((char *) nodeinfo.mess.Host, ptr[i + 1]);
        }
        if (strcasecmp(ptr[i], "Port") == 0) {
            if (strlen(ptr[i + 1]) >= sizeof (nodeinfo.mess.Port)) {
                *errtype = TYPESYNTAX;
                return (u_char *) SPORBIG;
            }
            strcpy((char *) nodeinfo.mess.Port, ptr[i + 1]);
        }
        if (strcasecmp(ptr[i], "Type") == 0) {
            if (strlen(ptr[i + 1]) >= sizeof (nodeinfo.mess.Type)) {
                *errtype = TYPESYNTAX;
                return (u_char *) STYPBIG;
            }
            strcpy((char *) nodeinfo.mess.Type, ptr[i + 1]);
        }
        if (strcasecmp(ptr[i], "Reversed") == 0) {
            if (strcasecmp(ptr[i + 1], "yes") == 0) {
                nodeinfo.mess.reversed = 1;
            }
        }
        if (strcasecmp(ptr[i], "flushpackets") == 0) {
            if (strcasecmp(ptr[i + 1], "on") == 0) {
                nodeinfo.mess.flushpackets = 1;
            } else if (strcasecmp(ptr[i + 1], "auto") == 0) {
                nodeinfo.mess.flushpackets = 0;
            }
        }
        if (strcasecmp(ptr[i], "flushwait") == 0) {
            nodeinfo.mess.flushwait = atoi(ptr[i + 1]) * 1000;
        }
        if (strcasecmp(ptr[i], "ping") == 0) {
            nodeinfo.mess.ping = ngx_time_from_sec(atoi(ptr[i + 1]));
        }
        if (strcasecmp(ptr[i], "smax") == 0) {
            nodeinfo.mess.smax = atoi(ptr[i + 1]);
        }
        if (strcasecmp(ptr[i], "ttl") == 0) {
            nodeinfo.mess.ttl = ngx_time_from_sec(atoi(ptr[i + 1]));
        }
        if (strcasecmp(ptr[i], "Timeout") == 0) {
            nodeinfo.mess.timeout = ngx_time_from_sec(atoi(ptr[i + 1]));
        }

        /* Hosts and contexts (optional paramters) */
        if (strcasecmp(ptr[i], "Alias") == 0) {
            if (phost->host && !phost->context) {
                *errtype = TYPESYNTAX;
                return (u_char *) SALIBAD;
            }
            if (phost->host) {
                phost->next = ngx_palloc(r->pool, sizeof (struct cluster_host));
                phost = phost->next;
                phost->next = NULL;
                phost->host = (u_char *) ptr[i + 1];
                phost->context = NULL;
            } else {
                phost->host = (u_char *) ptr[i + 1];
            }
        }
        if (strcasecmp(ptr[i], "Context") == 0) {
            if (phost->context) {
                *errtype = TYPESYNTAX;
                return (u_char *) SCONBAD;
            }
            phost->context = (u_char *) ptr[i + 1];
        }
        i++;
        i++;
    }

    /* Check for JVMRoute */
    if (nodeinfo.mess.JVMRoute[0] == '\0') {
        *errtype = TYPESYNTAX;
        return (u_char *) SROUBAD;
    }

    /* Insert or update balancer description */
    if (insert_update_balancer(balancerstatsmem, &balancerinfo) != NGX_OK) {
        *errtype = TYPEMEM;
        return (u_char *) MBALAUI;
    }

    /* check for removed node */
    node = read_node(nodestatsmem, &nodeinfo);
    if (node != NULL) {
        nodeinfo_t *node_copy = ngx_palloc(r->pool, sizeof (nodeinfo_t));
        ngx_memcpy(node_copy, &nodeinfo, sizeof (nodeinfo_t));
        /* If the node is removed (or kill and restarted) and recreated unchanged that is ok: network problems */
        if (!is_same_node(node, node_copy)) {
            /* Here we can't update it because the old one is still in */
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "process_config: node %s already exist", node->mess.JVMRoute);
            strcpy((char *) node->mess.JVMRoute, "REMOVED");
            node->mess.remove = 1;
            insert_update_node(nodestatsmem, node, &id);
            loc_remove_host_context(node->mess.id, r->pool);
            *errtype = TYPEMEM;
            return (u_char *) MNODERM;
        }
    }

    /* Insert or update node description */
    if (insert_update_node(nodestatsmem, &nodeinfo, &id) != NGX_OK) {
        *errtype = TYPEMEM;
        return (u_char *) MNODEUI;
    }

    /* Insert the Alias and corresponding Context */
    phost = vhost;
    if (phost->host == NULL && phost->context == NULL)
        goto done; /* Alias and Context missing */

    while (phost) {
        if (insert_update_hosts(hoststatsmem, phost->host, id, vid) != NGX_OK)
            return (u_char *) MHOSTUI;
        if (insert_update_contexts(contextstatsmem, phost->context, id, vid, STOPPED) != NGX_OK)
            return (u_char *) MCONTUI;
        phost = phost->next;
        vid++;
    }

done:
    *errtype = ngx_http_send_buffer(r, NULL, NGX_HTTP_OK);
    return NULL;
}

static u_char *process_dump(ngx_http_request_t *r, int *errtype) {
    int size, i;
    int *id;

    ngx_str_t ct = ngx_string("text/plain");
    ngx_str_t *ctp = &ct;
    r->headers_out.content_type_len = ct.len;
    r->headers_out.content_type = *ctp;

    size = loc_get_max_size_balancer();
    if (size == 0)
        return NULL;

    id = ngx_palloc(r->pool, sizeof (int) * size);
    size = get_ids_used_balancer(balancerstatsmem, id);


    ngx_buf_t *b = ngx_create_temp_buf(r->pool, 1024 * 32); // FIX-ME get some value to calculate real size

    for (i = 0; i < size; i++) {
        balancerinfo_t *ou;
        if (get_balancer(balancerstatsmem, &ou, id[i]) != NGX_OK)
            continue;
        ngx_bprintf(b, "balancer: [%d] Name: %*s Sticky: %d [%*s]/[%*s] remove: %d force: %d Timeout: %d maxAttempts: %d\n",
                id[i], ngx_strlen(ou->balancer), ou->balancer, ou->StickySession,
                ngx_strlen(ou->StickySessionCookie), ou->StickySessionCookie,
                ngx_strlen(ou->StickySessionPath), ou->StickySessionPath,
                ou->StickySessionRemove, ou->StickySessionForce,
                (int) ngx_time_from_sec(ou->Timeout),
                ou->Maxattempts);
    }

    size = loc_get_max_size_node();
    id = ngx_palloc(r->pool, sizeof (int) * size);
    size = get_ids_used_node(nodestatsmem, id);
    for (i = 0; i < size; i++) {
        nodeinfo_t *ou;
        if (get_node(nodestatsmem, &ou, id[i]) != NGX_OK)
            continue;
        ngx_bprintf(b, "node: [%d:%d],Balancer: %*s,JVMRoute: %*s,LBGroup: [%*s],Host: %*s,Port: %*s,Type: %*s,flushpackets: %d,flushwait: %d,ping: %d,smax: %d,ttl: %d,timeout: %d\n",
                id[i], ou->mess.id,
                ngx_strlen(ou->mess.balancer), ou->mess.balancer,
                ngx_strlen(ou->mess.JVMRoute), ou->mess.JVMRoute,
                ngx_strlen(ou->mess.Domain), ou->mess.Domain,
                ngx_strlen(ou->mess.Host), ou->mess.Host,
                ngx_strlen(ou->mess.Port), ou->mess.Port,
                ngx_strlen(ou->mess.Type), ou->mess.Type,
                ou->mess.flushpackets, ou->mess.flushwait / 1000, (int) ngx_sec_from_time(ou->mess.ping), ou->mess.smax,
                (int) ngx_sec_from_time(ou->mess.ttl), (int) ngx_sec_from_time(ou->mess.timeout));
    }

    size = loc_get_max_size_host();
    id = ngx_palloc(r->pool, sizeof (int) * size);
    size = get_ids_used_host(hoststatsmem, id);
    for (i = 0; i < size; i++) {
        hostinfo_t *ou;
        if (get_host(hoststatsmem, &ou, id[i]) != NGX_OK)
            continue;
        ngx_bprintf(b, "host: %d [%*s] vhost: %d node: %d\n", id[i], ngx_strlen(ou->host), ou->host, ou->vhost, ou->node);
    }

    size = loc_get_max_size_context();
    id = ngx_palloc(r->pool, sizeof (int) * size);
    size = get_ids_used_context(contextstatsmem, id);
    for (i = 0; i < size; i++) {
        contextinfo_t *ou;
        if (get_context(contextstatsmem, &ou, id[i]) != NGX_OK)
            continue;
        ngx_bprintf(b, "context: %d [%*s] vhost: %d node: %d status: %d\n", id[i],
                ngx_strlen(ou->context), ou->context,
                ou->vhost, ou->node,
                ou->status);
    }


    *errtype = ngx_http_send_buffer(r, b, NGX_HTTP_OK);

    return NULL;
}

/*
 * Process a INFO command.
 * Statics informations ;-)
 */
static u_char *process_info(ngx_http_request_t *r, int *errtype) {
    int size, i;
    int *id;

    ngx_str_t ct = ngx_string("text/plain");
    ngx_str_t *ctp = &ct;
    r->headers_out.content_type_len = ct.len;
    r->headers_out.content_type = *ctp;

    size = loc_get_max_size_node();

    ngx_buf_t *b;

    if (size == 0)
        return NULL;
    id = ngx_palloc(r->pool, sizeof (int) * size);
    size = get_ids_used_node(nodestatsmem, id);
    b = ngx_create_temp_buf(r->pool, (1024 * 2) * (size + 1)); // FIXED

    if (b == NULL)
        return NULL;

    for (i = 0; i < size; i++) {
        nodeinfo_t *ou;
        ///        proxy_worker_stat *proxystat;
        char *flushpackets;
        //       char *pptr;

        if (get_node(nodestatsmem, &ou, id[i]) != NGX_OK)
            continue;
        ngx_bprintf(b, "Node: [%d],Name: %*s,Balancer: %*s,LBGroup: %*s,Host: %*s,Port: %*s,Type: %*s",
                id[i],
                ngx_strlen(ou->mess.JVMRoute), ou->mess.JVMRoute,
                ngx_strlen(ou->mess.balancer), ou->mess.balancer,
                ngx_strlen(ou->mess.Domain), ou->mess.Domain,
                ngx_strlen(ou->mess.Host), ou->mess.Host,
                ngx_strlen(ou->mess.Port), ou->mess.Port,
                ngx_strlen(ou->mess.Type), ou->mess.Type);
        flushpackets = "Off";

        ngx_bprintf(b, ",Flushpackets: %s,Flushwait: %d,Ping: %d,Smax: %d,Ttl: %d",
                flushpackets, ou->mess.flushwait / 1000,
                (int) ngx_sec_from_time(ou->mess.ping),
                ou->mess.smax,
                (int) ngx_sec_from_time(ou->mess.ttl));

        /*pptr = (char *) ou;
        pptr = pptr + ou->offset;

        proxystat  = (proxy_worker_stat *) pptr;*/

        ngx_bprintf(b, ",Elected: 0,Read: 0,Transfered: 0,Connected: 0,Load: 0\n");

    }

    /* Process the Vhosts */
    size = loc_get_max_size_host();
    id = ngx_palloc(r->pool, sizeof (int) * size);
    size = get_ids_used_host(hoststatsmem, id);
    for (i = 0; i < size; i++) {
        hostinfo_t *ou;
        if (get_host(hoststatsmem, &ou, id[i]) != NGX_OK)
            continue;
        ngx_bprintf(b, "Vhost: [%d:%d:%d], Alias: %*s\n",
                ou->node, ou->vhost, id[i], ngx_strlen(ou->host), ou->host);
    }

    /* Process the Contexts */
    size = loc_get_max_size_context();
    id = ngx_palloc(r->pool, sizeof (int) * size);
    size = get_ids_used_context(contextstatsmem, id);
    for (i = 0; i < size; i++) {
        contextinfo_t *ou;
        char *status;
        if (get_context(contextstatsmem, &ou, id[i]) != NGX_OK)
            continue;
        status = "REMOVED";
        switch (ou->status) {
            case ENABLED:
                status = "ENABLED";
                break;
            case DISABLED:
                status = "DISABLED";
                break;
            case STOPPED:
                status = "STOPPED";
                break;
        }
        ngx_bprintf(b, "Context: [%d:%d:%d], Context: %*s, Status: %s\n",
                ou->node, ou->vhost, id[i],
                ngx_strlen(ou->context), ou->context,
                status);
    }


    *errtype = ngx_http_send_buffer(r, b, NGX_HTTP_OK);

    return NULL;
}

static void process_error(ngx_http_request_t *r, u_char *errstring, ngx_int_t errtype) {
    ngx_str_t version_key = ngx_string("Version");
    ngx_str_t version_value = ngx_string(VERSION_PROTOCOL);
    ngx_str_t type_key = ngx_string("Type");
    ngx_str_t type_mem_value = ngx_string("MEM");
    ngx_str_t type_syntax_value = ngx_string("SYNTAX");
    ngx_str_t type_general_value = ngx_string("GENERAL");
    ngx_str_t mess_key = ngx_string("Mess");
    ngx_str_t mess_value;
    mess_value.data = errstring;
    mess_value.len = ngx_strlen(errstring);

    ngx_set_custom_header(r, &version_key, &version_value);

    switch (errtype) {
        case TYPESYNTAX:
            ngx_set_custom_header(r, &type_key, &type_syntax_value);
            break;
        case TYPEMEM:
            ngx_set_custom_header(r, &type_key, &type_mem_value);
            break;
        default:
            ngx_set_custom_header(r, &type_key, &type_general_value);
            break;
    }
    ngx_set_custom_header(r, &mess_key, &mess_value);
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "manager_handler %V error: %s", &r->method_name, errstring);
}

static ngx_int_t ngx_http_manager_info_handler(ngx_http_request_t *r) {
    int node_size, max_node_size, i, sizesessionid;
    int *id;
    nodeinfo_t *nodes;
    int nbnodes = 0;
    u_char *domain = (u_char *) "";
    u_char *errstring = NULL;

    mod_manager_config *mconf = ngx_http_get_module_srv_conf(r, ngx_http_manager_module);


    /* process the parameters */
    if (r->args.len > 0) {
        ngx_str_t val = {0, 0};
        ngx_str_t val_uri_param = ngx_string("Refresh");
        ngx_str_t cmd = {0, 0};
        ngx_str_t cmd_uri_param = ngx_string("Cmd");
        ngx_str_t typ = {0, 0};
        ngx_str_t typ_uri_param = ngx_string("Range");
        ngx_str_t domain = {0, 0};
        ngx_str_t domain_uri_param = ngx_string("Domain");

        ngx_http_arg(r, val_uri_param.data, val_uri_param.len, &val);
        ngx_http_arg(r, cmd_uri_param.data, cmd_uri_param.len, &cmd);
        ngx_http_arg(r, typ_uri_param.data, typ_uri_param.len, &typ);
        ngx_http_arg(r, domain_uri_param.data, domain_uri_param.len, &domain);

        /* Process the Refresh parameter */
        if (val.len > 0) {
            long t = atol((char *) val.data);
            r->headers_out.accept_ranges = ngx_list_push(&r->headers_out.headers);
            if (r->headers_out.accept_ranges == NULL) {
                return NGX_ERROR;
            }

            r->headers_out.accept_ranges->hash = 1;
            ngx_str_set(&r->headers_out.accept_ranges->key, "Refresh");
            ngx_str_set(&r->headers_out.accept_ranges->value, ngx_ltoa(r->pool, t < 1 ? 10 : t));

        }

        /* Process INFO and DUMP */
        if (cmd.len > 0) {
            int errtype = 0;
            if (ngx_strncasecmp(cmd.data, (u_char *) "DUMP", cmd.len) == 0) {
                errstring = process_dump(r, &errtype);
                if (!errstring)
                    return NGX_OK;
            } else if (ngx_strncasecmp(cmd.data, (u_char *) "INFO", cmd.len) == 0) {
                errstring = process_info(r, &errtype);
                if (!errstring)
                    return NGX_OK;
            }
            if (errstring) {
                process_error(r, errstring, errtype);
            }
        }

        /* Process other command if any */
        if (cmd.len > 0 && typ.len > 0 && mconf->allow_cmd && errstring == NULL) {
            int global = RANGECONTEXT;
            int errtype = 0;

            if (ngx_strncasecmp(typ.data, (u_char *) "NODE", typ.len) == 0)
                global = RANGENODE;
            else if (ngx_strncasecmp(typ.data, (u_char *) "DOMAIN", typ.len) == 0)
                global = RANGEDOMAIN;

            u_char **ptr = process_buff(r, r->args.data);

            if (global == RANGEDOMAIN)
                errstring = process_domain(r, ptr, &errtype, cmd.data, domain.data);
            else if (ngx_strncasecmp(cmd.data, (u_char *) "ENABLE-APP", cmd.len) == 0)
                errstring = process_enable(r, ptr, &errtype, global);
            else if (ngx_strncasecmp(cmd.data, (u_char *) "DISABLE-APP", cmd.len) == 0)
                errstring = process_disable(r, ptr, &errtype, global);
            else if (ngx_strncasecmp(cmd.data, (u_char *) "STOP-APP", cmd.len) == 0)
                errstring = process_stop(r, ptr, &errtype, global, 0);
            else if (ngx_strncasecmp(cmd.data, (u_char *) "REMOVE-APP", cmd.len) == 0)
                errstring = process_remove(r, ptr, &errtype, global);
            else {
                errstring = (u_char*) SCMDUNS;
                errtype = TYPESYNTAX;
            }
            if (errstring) {
                process_error(r, errstring, errtype);
            }
        }
    }

    sizesessionid = loc_get_max_size_sessionid();

    max_node_size = loc_get_max_size_node();

    if (max_node_size == 0)
        return NGX_OK;

    id = ngx_palloc(r->pool, sizeof (int) * max_node_size);

    if (id == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    node_size = get_ids_used_node(nodestatsmem, id);

    ngx_buf_t *b = ngx_create_temp_buf(r->pool, (((1024 * 2) + (128 * sizesessionid)) * (node_size + 1))); // FIXED

    if (b == NULL) {
        return NGX_ERROR;
    }

    ngx_str_t ct = ngx_string("text/html; charset=ISO-8859-1");
    ngx_str_t *ctp = &ct;
    r->headers_out.content_type_len = ct.len;
    r->headers_out.content_type = *ctp;


    ngx_bprintf(b, DOCTYPE_HTML_3_2 "<html><head>\n<title>Mod_cluster Status</title>\n</head><body>\n");
    ngx_bprintf(b, "<h1>" MOD_CLUSTER_EXPOSED_VERSION "</h1>");

    if (errstring) {
        ngx_bprintf(b, "<h1> Command failed: %s </h1>\n", errstring);
        ngx_bprintf(b, " <a href=\"%V\">Continue</a>\n", &r->uri);
        ngx_bprintf(b, "</body></html>\n");
        return NGX_OK;
    }

    /* Advertise information */
    if (mconf->allow_display) {
        //if (advertise_info != NULL)
            advertise_info(r, b);
        ngx_bprintf(b, "end of \"httpd.conf\" configuration<br/><br/>");
    }

    ngx_bprintf(b, "<a href=\"%V?%srefresh=10\">Auto Refresh</a>", &r->uri, balancer_nonce_string(r));

    ngx_bprintf(b, " <a href=\"%V?%sCmd=DUMP&Range=ALL\">show DUMP output</a>", &r->uri, balancer_nonce_string(r));

    ngx_bprintf(b, " <a href=\"%V?%sCmd=INFO&Range=ALL\">show INFO output</a>", &r->uri, balancer_nonce_string(r));

    ngx_bprintf(b, "\n");

    /* read the node to sort them by domain */
    nodes = ngx_palloc(r->pool, sizeof (nodeinfo_t) * node_size);
    for (i = 0; i < node_size; i++) {
        nodeinfo_t *ou;
        if (get_node(nodestatsmem, &ou, id[i]) != NGX_OK)
            continue;
        memcpy(&nodes[nbnodes], ou, sizeof (nodeinfo_t));
        nbnodes++;
    }
    sort_nodes(nodes, nbnodes);

    /* display the ordered nodes */
    for (i = 0; i < node_size; i++) {
        char *flushpackets;
        nodeinfo_t *ou = &nodes[i];
        char *pptr = (char *) ou;

        if (ngx_strcmp(domain, ou->mess.Domain) != 0) {
            if (mconf->reduce_display)
                ngx_bprintf(b, "<br/><br/>LBGroup %*s: ", ngx_strlen(ou->mess.Domain), ou->mess.Domain);
            else
                ngx_bprintf(b, "<h1> LBGroup %*s: ", ngx_strlen(ou->mess.Domain), ou->mess.Domain);
            domain = ou->mess.Domain;
            if (mconf->allow_cmd)
                domain_command_string(r, domain, b);
            if (!mconf->reduce_display)
                ngx_bprintf(b, "</h1>\n");
        }
        if (mconf->reduce_display)
            ngx_bprintf(b, "<br/><br/>Node %*s ",
                ngx_strlen(ou->mess.JVMRoute), ou->mess.JVMRoute);
        else
            ngx_bprintf(b, "<h1> Node %*s (%*s://%*s:%*s): </h1>\n",
                ngx_strlen(ou->mess.JVMRoute), ou->mess.JVMRoute,
                ngx_strlen(ou->mess.Type), ou->mess.Type,
                ngx_strlen(ou->mess.Host), ou->mess.Host,
                ngx_strlen(ou->mess.Port), ou->mess.Port);
        pptr = pptr + ou->offset;
        if (mconf->reduce_display) {
            //      printproxy_stat(r, mconf->reduce_display, (proxy_worker_stat *) pptr);
        }

        if (mconf->allow_cmd)
            node_command_string(r, ou->mess.JVMRoute, b);

        if (!mconf->reduce_display) {
            ngx_bprintf(b, "<br/>\n");
            ngx_bprintf(b, "Balancer: %*s,LBGroup: %*s", ngx_strlen(ou->mess.balancer), ou->mess.balancer,
                    ngx_strlen(ou->mess.Domain), ou->mess.Domain);

            flushpackets = "Off";

            ngx_bprintf(b, ",Flushpackets: %s,Flushwait: %d,Ping: %d,Smax: %d,Ttl: %d",
                    flushpackets, ou->mess.flushwait,
                    (int) ngx_sec_from_time(ou->mess.ping), ou->mess.smax, (int) ngx_sec_from_time(ou->mess.ttl));
        }

        if (mconf->reduce_display)
            ngx_bprintf(b, "<br/>\n");
        else {
            //            printproxy_stat(r, mconf->reduce_display, (proxy_worker_stat *) pptr);
        }

        if (sizesessionid) {
            ngx_bprintf(b, ",Num sessions: %d", count_sessionid(r, ou->mess.JVMRoute));
        }
        ngx_bprintf(b, "\n");

        /* Process the Vhosts */
        manager_info_hosts(r, mconf->reduce_display, mconf->allow_cmd, ou->mess.id, ou->mess.JVMRoute, b);
    }
    /* Display the sessions */
    if (sizesessionid)
        manager_sessionid(r, b);


    ngx_bprintf(b, "</body></html>\n");


    return ngx_http_send_buffer(r, b, NGX_HTTP_OK);
}

/*
 * JGroups feature routines
 */
static u_char *process_addid(ngx_http_request_t *r, u_char **uptr, int *errtype) {
    jgroupsidinfo_t jgroupsid;
    int i = 0;
    char **ptr = (char **) uptr;
    jgroupsid.jgroupsid[0] = '\0';
    while (ptr[i]) {
        if (strcasecmp(ptr[i], "JGroupUuid") == 0) {
            if (strlen(ptr[i + 1]) >= sizeof (jgroupsid.jgroupsid)) {
                *errtype = TYPESYNTAX;
                return (u_char *) SJIDBIG;
            }
            strcpy(jgroupsid.jgroupsid, ptr[i + 1]);
        }
        if (strcasecmp(ptr[i], "JGroupData") == 0) {
            if (strlen(ptr[i + 1]) >= sizeof (jgroupsid.data)) {
                *errtype = TYPESYNTAX;
                return (u_char *) SJDDBIG;
            }
            strcpy(jgroupsid.data, ptr[i + 1]);
        }
        i++;
        i++;
    }
    if (jgroupsid.jgroupsid[0] == '\0') {
        *errtype = TYPESYNTAX;
        return (u_char *) SJIDBAD;
    }
    if (insert_update_jgroupsid(jgroupsidstatsmem, &jgroupsid) != NGX_OK) {
        *errtype = TYPEMEM;
        return (u_char *) MJBIDUI;
    }

    return NULL;
}

static u_char *process_removeid(ngx_http_request_t *r, u_char **uptr, int *errtype) {
    jgroupsidinfo_t jgroupsid;
    int i = 0;
    char **ptr = (char **) uptr;

    jgroupsid.jgroupsid[0] = '\0';
    while (ptr[i]) {
        if (strcasecmp(ptr[i], "JGroupUuid") == 0) {
            if (strlen(ptr[i + 1]) >= sizeof (jgroupsid.jgroupsid)) {
                *errtype = TYPESYNTAX;
                return (u_char *) SJIDBIG;
            }
            strcpy(jgroupsid.jgroupsid, ptr[i + 1]);
        }
        i++;
        i++;
    }
    if (jgroupsid.jgroupsid[0] == '\0') {
        *errtype = TYPESYNTAX;
        return (u_char *) SJIDBAD;
    }
    remove_jgroupsid(jgroupsidstatsmem, &jgroupsid);
    return NULL;
}

/*
 * Query out should be something like:
 * JGroup: [9],JGroupUuid: node4, JGroupData: jgroupdata4
 * JGroup: [11],JGroupUuid: node6, JGroupData: jgroupdata6
 */
static void print_jgroupsid(ngx_buf_t *r, int id, jgroupsidinfo_t *jgroupsid) {
    ngx_bprintf(r, "JGroup: [%d],JGroupUuid: %*s,JGroupData: %*s\n",
            id,
            ngx_strlen(jgroupsid->jgroupsid), jgroupsid->jgroupsid,
            ngx_strlen(jgroupsid->data), jgroupsid->data);
}

static u_char *process_query(ngx_http_request_t *r, u_char **uptr, int *errtype) {
    jgroupsidinfo_t jgroupsid;
    int i = 0;
    char **ptr = (char **) uptr;

    jgroupsid.jgroupsid[0] = '\0';
    while (ptr[i]) {
        if (strcasecmp(ptr[i], "JGroupUuid") == 0) {
            if (strlen(ptr[i + 1]) >= sizeof (jgroupsid.jgroupsid)) {
                *errtype = TYPESYNTAX;
                return (u_char *) SJIDBIG;
            }
            strcpy(jgroupsid.jgroupsid, ptr[i + 1]);
        }
        i++;
        i++;
    }
    if (jgroupsid.jgroupsid[0] == '\0') {
        jgroupsid.jgroupsid[0] = '*';
        jgroupsid.jgroupsid[1] = '\0';
    }

    ngx_buf_t *b = ngx_create_temp_buf(r->pool, 1024 * 2);

    if (strcmp(jgroupsid.jgroupsid, "*") == 0) {
        int size, i;
        int *id;
        size = loc_get_max_size_jgroupsid();
        if (size == 0)
            return NULL;
        id = ngx_palloc(r->pool, sizeof (int) * size);
        size = get_ids_used_jgroupsid(jgroupsidstatsmem, id);
        for (i = 0; i < size; i++) {
            jgroupsidinfo_t *ou;
            if (get_jgroupsid(jgroupsidstatsmem, &ou, id[i]) != NGX_OK)
                continue;
            print_jgroupsid(b, id[i], ou);
        }
    } else {
        jgroupsidinfo_t *ou;
        ou = read_jgroupsid(jgroupsidstatsmem, &jgroupsid);
        if (ou == NULL) {
            *errtype = TYPEMEM;
            return (u_char *) MJBIDRD;
        } else
            print_jgroupsid(b, ou->id, ou);
    }

    ngx_chain_t out;

    out.buf = b;
    out.next = NULL;

    *errtype = ngx_http_output_filter(r, &out);

    return NULL;
}

static void ngx_http_manager_body_handler(ngx_http_request_t *r) {
    u_char *errstring = NULL;
    int errtype = 0;
    u_char *buff = NULL;
    size_t bufsiz = 0, maxbufsiz;// len;
    ngx_chain_t *chain_buf = r->request_body->bufs;
    size_t bufpos = 0;
    int global = 0;
    u_char **ptr;

    mod_manager_config *mconf;

    mconf = ngx_http_get_module_srv_conf(r, ngx_http_manager_module);

    /* Use a buffer to read the message */
    if (mconf->maxmesssize)
        maxbufsiz = mconf->maxmesssize;
    else {
        /* we calculate it */
        maxbufsiz = 9 + JVMROUTESZ;
        maxbufsiz = bufsiz + (mconf->maxhost * HOSTALIASZ) + 7;
        maxbufsiz = bufsiz + (mconf->maxcontext * CONTEXTSZ) + 8;
    }
    if (maxbufsiz < MAXMESSSIZE)
        maxbufsiz = MAXMESSSIZE;

    if (!buff)
        buff = ngx_pcalloc(r->pool, maxbufsiz);

    if (!buff) {
        process_error(r, (u_char *) SMESPAR, TYPESYNTAX);
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    //len = maxbufsiz;

    while (chain_buf && bufpos < maxbufsiz) {
        ngx_memcpy(buff + bufpos, chain_buf->buf->pos, chain_buf->buf->last - chain_buf->buf->pos);
        bufpos += (chain_buf->buf->last - chain_buf->buf->pos);
        chain_buf = chain_buf->next;
    }

    /* XXX: Size limit it? */
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "manager_handler %V (%V) processing: \"%*s\"", &r->method_name, &r->uri, bufpos, buff);

    decodeenc(buff);
    ptr = process_buff(r, buff);

    if (ptr == NULL) {
        process_error(r, (u_char *) SMESPAR, TYPESYNTAX);
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
     
    int i = (u_char * )ngx_strstr (r->uri_start, " ") - r->uri_start;
    if (ngx_strcmp(r->uri_start, "*") == 0 || (i >= 2 && r->uri_start[i - 1] == '*' && r->uri_start[i - 2] == '/')) {
        global = 1;
    }
    

    if (ngx_strncasecmp(r->method_name.data, (u_char *) "CONFIG", r->method_name.len) == 0)
        errstring = process_config(r, ptr, &errtype);
        /* Application handling */
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "ENABLE-APP", r->method_name.len) == 0)
        errstring = process_enable(r, ptr, &errtype, global);
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "DISABLE-APP", r->method_name.len) == 0)
        errstring = process_disable(r, ptr, &errtype, global);
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "STOP-APP", r->method_name.len) == 0)
        errstring = process_stop(r, ptr, &errtype, global, 1);
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "REMOVE-APP", r->method_name.len) == 0)
        errstring = process_remove(r, ptr, &errtype, global);
        /* Status handling */
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "STATUS", r->method_name.len) == 0)
        errstring = process_status(r, ptr, &errtype);
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "DUMP", r->method_name.len) == 0)
        errstring = process_dump(r, &errtype);
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "INFO", r->method_name.len) == 0)
        errstring = process_info(r, &errtype);
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "PING", r->method_name.len) == 0)
        errstring = process_ping(r, ptr, &errtype);
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "ADDID", r->method_name.len) == 0)
        errstring = process_addid(r, ptr, &errtype);
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "REMOVEID", r->method_name.len) == 0)
        errstring = process_removeid(r, ptr, &errtype);
    else if (ngx_strncasecmp(r->method_name.data, (u_char *) "QUERY", r->method_name.len) == 0)
        errstring = process_query(r, ptr, &errtype);
    else {
        errstring = (u_char *) SCMDUNS;
        errtype = TYPESYNTAX;
    }

    /* Check error string and build the error message */
    if (errstring) {
        process_error(r, errstring, errtype);
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "manager_handler %V  OK", &r->method_name);

    ngx_http_finalize_request(r, NGX_HTTP_OK);

    return;
}

ngx_int_t ngx_http_proxy_manager_handler(ngx_http_request_t *r);

/* Process the requests from the ModClusterService */
static ngx_int_t ngx_http_manager_handler(ngx_http_request_t *r) {

    ngx_int_t status;
    int ours = 0;

    mod_manager_config *mconf;

    mconf = ngx_http_get_module_srv_conf(r, ngx_http_manager_module);

    if (!mconf->enable_mcpm_receive)
        return NGX_DECLINED; /* Not allowed to receive MCMP */

    ours = check_method(r);

    if (!ours) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Here we should pass to proxy, and their upstreams");
        return ngx_http_proxy_manager_handler(r);
    }
    
    status = ngx_http_read_client_request_body(r, ngx_http_manager_body_handler);

    if (status >= NGX_HTTP_SPECIAL_RESPONSE) {
        return status;
    }

    return (NGX_DONE);
}

ngx_int_t ngx_http_proxy_add_variables(ngx_conf_t *cf);

static ngx_int_t ngx_http_manager_preconfiguration(ngx_conf_t *cf) {

    ngx_pool_t *global_pool;

    global_pool = ngx_create_pool(1024, cf->log);
    if (!global_pool) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, 0, "Fatal error: unable to create global pool for shared slotmem");
        return NGX_ERROR;
    }
    mem_getstorage(global_pool, "");

    ngx_http_proxy_add_variables(cf);

    return NGX_OK;
}

void *ngx_http_proxy_create_loc_conf(ngx_http_proxy_loc_conf_t *conf);

static ngx_int_t ngx_http_manager_postconfiguration(ngx_conf_t *cf) {

    u_char *node;
    u_char *context;
    u_char *host;
    u_char *balancer;
    u_char *sessionid;
    u_char *domain;
    u_char *jgroupsid;

    //    int i;

    uuid_t uuid;
    mod_manager_config *mconf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_manager_module);


    if (!mconf->basefilename.data) {
        mconf->basefilename.data = ngx_pstrcat(cf->pool, "/tmp", NULL);
        mconf->basefilename.len = sizeof ("/tmp") - 1;
    }

    node = ngx_pstrcat(cf->pool, mconf->basefilename.data, "/manager.node", NULL);
    context = ngx_pstrcat(cf->pool, mconf->basefilename.data, "/manager.context", NULL);
    host = ngx_pstrcat(cf->pool, mconf->basefilename.data, "/manager.host", NULL);
    balancer = ngx_pstrcat(cf->pool, mconf->basefilename.data, "/manager.balancer", NULL);
    sessionid = ngx_pstrcat(cf->pool, mconf->basefilename.data, "/manager.sessionid", NULL);
    domain = ngx_pstrcat(cf->pool, mconf->basefilename.data, "/manager.domain", NULL);
    jgroupsid = ngx_pstrcat(cf->pool, mconf->basefilename.data, "/manager.jgroupsid", NULL);


    /* Do some sanity checks */
    if (mconf->maxhost < mconf->maxnode)
        mconf->maxhost = mconf->maxnode;
    if (mconf->maxcontext < mconf->maxhost)
        mconf->maxcontext = mconf->maxhost;

    /* Get a provider to handle the shared memory */
    storage = mem_getstorage(NULL, "");
    storage->cf = cf;
    storage->ngx_http_module = &ngx_http_manager_module_ctx;

    ngx_pool_t *p = cf->pool;

    if (storage == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ap_lookup_provider %s failed", SLOTMEM_STORAGE);
        return !NGX_OK;
    }
    nodestatsmem = create_mem_node(node, &mconf->maxnode, mconf->persistent, p, storage);
    if (nodestatsmem == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "create_mem_node %s failed", node);
        return !NGX_OK;
    }
    if (get_last_mem_error(nodestatsmem) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "create_mem_node %s failed: %d", node, get_last_mem_error(nodestatsmem));
        return !NGX_OK;
    }

    contextstatsmem = create_mem_context(context, &mconf->maxcontext, mconf->persistent, p, storage);
    if (contextstatsmem == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "create_mem_context failed");
        return !NGX_OK;
    }

    hoststatsmem = create_mem_host(host, &mconf->maxhost, mconf->persistent, p, storage);
    if (hoststatsmem == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "create_mem_host failed");
        return !NGX_OK;
    }

    balancerstatsmem = create_mem_balancer(balancer, &mconf->maxhost, mconf->persistent, p, storage);
    if (balancerstatsmem == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "create_mem_balancer failed");
        return !NGX_OK;
    }

    sessionidstatsmem = create_mem_sessionid(sessionid, &mconf->maxsessionid, mconf->persistent, p, storage);
    if (sessionidstatsmem == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "create_mem_sessionid failed");
        return !NGX_OK;
    }

    domainstatsmem = create_mem_domain(domain, &mconf->maxnode, mconf->persistent, p, storage);
    if (domainstatsmem == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "create_mem_domain failed");
        return !NGX_OK;
    }

    jgroupsidstatsmem = create_mem_jgroupsid(jgroupsid, &mconf->maxjgroupsid, mconf->persistent, p, storage);
    if (jgroupsidstatsmem == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "create_mem_jgroupsid failed");
        return !NGX_OK;
    }


    /* Get a provider to ping/pong logics */
    /*
        balancerhandler = ap_lookup_provider("proxy_cluster", "balancer", "0");
        if (balancerhandler == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "can't find a ping/pong logic");
        }
     */

    /*
     * Retrieve a UUID and store the nonce.
     */
    uuid_create(&uuid);
    snpuid(balancer_nonce, sizeof (balancer_nonce), uuid);

    /*
     * clean up to prevent backgroup thread (proxy_cluster_watchdog_func) to crash
     */
    ngx_pool_cleanup_t *cln;

    cln = ngx_pool_cleanup_add(p, 0);
    if (cln) {
        cln->handler = cleanup_manager;
        cln->data = cf;
    }

    sharedmem_initialize_cleanup(p);

    return NGX_OK;
}

/*
 * remove the domain that have timeout
 */
static void remove_timeout_domain() {
    int id[DEFMAXHOST], size, i;
    time_t now;

    now = time(NULL);

    /* read the ident of the domain */
    size = domain_storage.get_max_size_domain();
    if (size == 0)
        return;

    size = domain_storage.get_ids_used_domain(id);

    for (i=0; i<size; i++) {
        domaininfo_t *ou;
        if (domain_storage.read_domain(id[i], &ou) != NGX_OK)
            continue;
        if (ou->updatetime < (now - TIMEDOMAIN)) {
            /* Remove it */
            domain_storage.remove_domain(ou);
        } 
    } 
}

static void remove_removed_nodes() {
   int id[DEFMAXHOST], size, i;

    /* read the ident of the nodes */
    size = node_storage.get_max_size_node();
    if (size == 0) {
        return;
    }
    size = node_storage.get_ids_used_node(id);
    for (i = 0; i < size; i++) {
        nodeinfo_t *ou;
        if (node_storage.read_node(id[i], &ou) != NGX_OK)
            continue;
        if (ou->mess.remove) {
             if (ou->mess.Domain[0] != '\0') {
                domaininfo_t dom;
                ngx_memcpy(dom.JVMRoute, ou->mess.JVMRoute, ngx_strlen(ou->mess.JVMRoute));
                ngx_memcpy(dom.balancer, ou->mess.balancer, ngx_strlen(ou->mess.balancer));
                ngx_memcpy(dom.domain, ou->mess.Domain, ngx_strlen(ou->mess.Domain));
                if (domain_storage.insert_update_domain(&dom) != NGX_OK) {
                    remove_timeout_domain();
                    domain_storage.insert_update_domain(&dom);
                }
            }            
             /* remove the node from the shared memory */
            node_storage.remove_host_context(ou->mess.id, NULL);
            node_storage.remove_node(ou);
        }
    }
}

static void remove_timeout_sessionid() {

    int id[DEFMAXCONTEXT], size, i;
    time_t now;

    now = time(NULL);

    /* read the ident of the sessionid */
    size = sessionid_storage.get_max_size_sessionid();
    if (size == 0)
        return;
    
    size = sessionid_storage.get_ids_used_sessionid(id);

    /* update lbstatus if needed */
    for (i = 0; i < size; i++) {
        sessionidinfo_t *ou;
        if (sessionid_storage.read_sessionid(id[i], &ou) != NGX_OK)
            continue;
        if (ou->updatetime < (now - TIMESESSIONID)) {
            /* Remove it */
            sessionid_storage.remove_sessionid(ou);
        }
    }
}

static void check_nodes() {
    int id[DEFMAXHOST], size, i;
    //time_t now;

    //now = time(NULL);

    /* read the ident of the nodes */
    size = node_storage.get_max_size_node();
    if (size == 0)
        return;
    
    size = node_storage.get_ids_used_node(id);

    /* update lbstatus if needed */
    for (i=0; i<size; i++) {
        nodeinfo_t *ou;
        if (node_storage.read_node(id[i], &ou) != NGX_OK)
            continue;
        if (ou->mess.remove)
            continue;
        /* Test for broken nodes */
        
    }
}

static ngx_event_t clean_timer;
static void ngx_clean_timer_handler(ngx_event_t *ev) {    
    //mod_manager_config *mconf = ev->data;
    ngx_log_error(NGX_LOG_DEBUG, ev->log, 0, "Event fired!");
    check_nodes();
    
    /* removed nodes: check for workers */
    remove_removed_nodes();
   
    
    /* Free sessionid slots */
    if (sessionid_storage.get_max_size_sessionid() > 0)
        remove_timeout_sessionid();
        
    if (ngx_exiting) {
        return;
    }
    clean_timer.log = ev->log;
    clean_timer.handler = ngx_clean_timer_handler;
    ngx_add_timer(&clean_timer, 10000);
}

/*
 * Initialize Shared Memory 
 */
static ngx_int_t ngx_http_manager_module_init(ngx_cycle_t *cycle) {

    u_char *node;
    u_char *context;
    u_char *host;
    u_char *balancer;
    u_char *sessionid;
    u_char *domain;
    u_char *jgroupsid;
    ngx_int_t rv = NGX_OK;

    mod_manager_config *mconf = NULL;

    if (ngx_get_conf(cycle->conf_ctx, ngx_http_module)) {
        ngx_http_conf_ctx_t *ctx = (ngx_http_conf_ctx_t *) ngx_get_conf(cycle->conf_ctx, ngx_http_module);
        mconf = ngx_http_get_module_srv_conf(ctx, ngx_http_manager_module);
    }

    if (!mconf)
        return !NGX_OK;

    if (!mconf->basefilename.data) {
        mconf->basefilename.data = ngx_pstrcat(cycle->pool, "/tmp", NULL);
        mconf->basefilename.len = sizeof ("/tmp") - 1;
    }

    node = ngx_pstrcat(cycle->pool, mconf->basefilename.data, "/manager.node", NULL);
    context = ngx_pstrcat(cycle->pool, mconf->basefilename.data, "/manager.context", NULL);
    host = ngx_pstrcat(cycle->pool, mconf->basefilename.data, "/manager.host", NULL);
    balancer = ngx_pstrcat(cycle->pool, mconf->basefilename.data, "/manager.balancer", NULL);
    sessionid = ngx_pstrcat(cycle->pool, mconf->basefilename.data, "/manager.sessionid", NULL);
    domain = ngx_pstrcat(cycle->pool, mconf->basefilename.data, "/manager.domain", NULL);
    jgroupsid = ngx_pstrcat(cycle->pool, mconf->basefilename.data, "/manager.jgroupsid", NULL);


    /* Do some sanity checks */
    if (mconf->maxhost < mconf->maxnode)
        mconf->maxhost = mconf->maxnode;
    if (mconf->maxcontext < mconf->maxhost)
        mconf->maxcontext = mconf->maxhost;


    ngx_pool_t *p = cycle->pool;

    if (storage == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "ap_lookup_provider %s failed", SLOTMEM_STORAGE);
        return !NGX_OK;
    }

    if (nodestatsmem != NULL) {
        rv = init_mem_node(nodestatsmem, node, &mconf->maxnode, p);
        if (rv != NGX_OK)
            return !NGX_OK;
    } else {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Sharedmemory init: init_mem_node failed");
        return !NGX_OK;
    }

    if (contextstatsmem != NULL) {
        rv = init_mem_context(contextstatsmem, context, &mconf->maxcontext, p);
        if (rv != NGX_OK)
            return !NGX_OK;
    } else {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Sharedmemory init: init_mem_context failed");
        return !NGX_OK;
    }

    if (hoststatsmem != NULL) {
        rv = init_mem_host(hoststatsmem, host, &mconf->maxhost, p);
        if (rv != NGX_OK)
            return !NGX_OK;
    } else {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Sharedmemory init: init_mem_host failed");
        return !NGX_OK;
    }

    if (balancerstatsmem != NULL) {
        rv = init_mem_balancer(balancerstatsmem, balancer, &mconf->maxhost, p);
        if (rv != NGX_OK)
            return !NGX_OK;
    } else {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Sharedmemory init: init_mem_balancer failed");
        return !NGX_OK;
    }

    if (sessionidstatsmem != NULL) {
        rv = init_mem_sessionid(sessionidstatsmem, sessionid, &mconf->maxsessionid, p);
        if (rv != NGX_OK)
            return !NGX_OK;
    } else {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Sharedmemory init: init_mem_sessionid failed");
        return !NGX_OK;
    }

    if (domainstatsmem != NULL) {
        rv = init_mem_domain(domainstatsmem, domain, &mconf->maxnode, p);
        if (rv != NGX_OK)
            return !NGX_OK;
    } else {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Sharedmemory init: init_mem_domain failed");
        return !NGX_OK;
    }

    if (jgroupsidstatsmem != NULL) {
        rv = init_mem_jgroupsid(jgroupsidstatsmem, jgroupsid, &mconf->maxjgroupsid, p);
        if (rv != NGX_OK)
            return !NGX_OK;
    } else {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Sharedmemory init: init_mem_jgroupsid failed");
        return !NGX_OK;
    }

    return rv;
}

/*
 * Create the mutex of the insert/remove logic
 */
static ngx_int_t ngx_http_manager_child_init(ngx_cycle_t *cycle) {
    mod_manager_config *mconf = NULL;

    if (ngx_get_conf(cycle->conf_ctx, ngx_http_module)) {
        ngx_http_conf_ctx_t *ctx = (ngx_http_conf_ctx_t *) ngx_get_conf(cycle->conf_ctx, ngx_http_module);
        mconf = ngx_http_get_module_srv_conf(ctx, ngx_http_manager_module);
    }

    if (mconf) {
        clean_timer.log = ngx_cycle->log;
        clean_timer.handler = ngx_clean_timer_handler;
        clean_timer.data = mconf;
        ngx_add_timer(&clean_timer, (ngx_msec_t) 10000);
    }
    return sharedmem_initialize_child(cycle->pool);
}

ngx_int_t ngx_http_upstream_init_fair(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us);

/*
 * Config creation stuff
 */
static void *ngx_http_module_manager_create_manager_config(ngx_conf_t *cf) {
    mod_manager_config *mconf = ngx_pcalloc(cf->pool, sizeof (*mconf));
    int i;

    if (mconf == NULL) {
        return NGX_CONF_ERROR;
    }

    mconf->basefilename.data = NULL;
    mconf->basefilename.len = 0;

    mconf->maxcontext = DEFMAXCONTEXT;
    mconf->maxnode = DEFMAXNODE;
    mconf->maxhost = DEFMAXHOST;
    mconf->maxsessionid = DEFMAXSESSIONID;
    mconf->maxjgroupsid = DEFMAXJGROUPSID;
    mconf->tableversion = 0;
    mconf->persistent = 0;
    mconf->nonce = -1;
    mconf->balancername.data = NULL;
    mconf->balancername.len = 0;
    mconf->allow_display = 0;
    mconf->allow_cmd = -1;
    mconf->reduce_display = 0;
    mconf->enable_mcpm_receive = 0;

    for (i = 0; i < DEFMAXCONTEXT; i++) {
        ngx_http_proxy_loc_conf_t *plcf;
        int j;

        plcf = ngx_pcalloc(cf->pool, sizeof (ngx_http_proxy_loc_conf_t));

        if (plcf == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_http_proxy_create_loc_conf(plcf);

        ngx_http_upstream_srv_conf_t *uscf;

        uscf = ngx_pcalloc(cf->pool, sizeof (ngx_http_upstream_srv_conf_t));
        uscf->file_name = (u_char*) "dynamic_generated";

        ngx_array_t *servers = ngx_pcalloc(cf->pool, sizeof (ngx_array_t));

        if (!servers || ngx_array_init(servers, cf->pool, DEFMAXHOST, sizeof (ngx_http_upstream_server_t)) != NGX_OK) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_array_init failed ngx_http_upstream_server_t");
            return NGX_CONF_ERROR;
        }

        for (j = 0; j < DEFMAXHOST; j++) {
            ngx_http_upstream_server_t *us;
            ngx_url_t u;
            ngx_str_t localhost = ngx_string("255.255.255.255");
            us = ngx_array_push(servers);

            ngx_memzero(us, sizeof (ngx_http_upstream_server_t));

            ngx_memzero(&u, sizeof (ngx_url_t));

            u.url = localhost;
            u.default_port = 80;

            if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
                if (u.err) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s in upstream \"%V\"", u.err, &u.url);
                }

                return NGX_CONF_ERROR;
            }

            us->addrs = u.addrs;
            us->naddrs = u.naddrs;
            us->weight = 1;
            us->max_fails = 1;
            us->fail_timeout = 10;

        }


        uscf->servers = servers;

        ngx_http_upstream_init_fair(cf, uscf);

        ngx_http_upstream_fair_peers_t *peers = uscf->peer.data;

        plcf->max_peers_number = peers->number;

        peers->number = 0;

        plcf->upstream.upstream = uscf;

        plcf->updatetime = time(NULL);

        mconf->plcf[i] = plcf;
    }

    mconf->clean_timer = ngx_pcalloc(cf->pool, sizeof (ngx_event_t));
    if (mconf->clean_timer == NULL) {    
        return NGX_CONF_ERROR;
    }

    return mconf;
}
