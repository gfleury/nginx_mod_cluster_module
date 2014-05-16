/* 
 * File:   node.h
 * Author: georgefleury
 *
 * Created on April 17, 2014, 11:03 PM
 */

#ifndef NODE_H
#define	NODE_H


/**
 * @file  node.h
 * @brief node description Storage Module for Apache
 *
 * @defgroup MEM nodes
 * @ingroup  APACHE_MODS
 * @{
 */

#define NODEEXE ".nodes"

#ifndef MEM_T
typedef struct mem mem_t; 
#define MEM_T
#endif

#include "mod_clustersize.h"


/* configuration of the node received from jboss cluster. */
struct nodemess {
    u_char balancer[BALANCERSZ];        /* name of the balancer */
    u_char JVMRoute[JVMROUTESZ];
    u_char Domain[DOMAINNDSZ];
    u_char Host[HOSTNODESZ];
    u_char Port[PORTNODESZ];
    u_char Type[SCHEMENDSZ];
    int  reversed; /* 1 : reversed... 0 : normal */
    int  remove;   /* 1 : removed     0 : normal */

    /* node conf part */
    int flushpackets;
    int	flushwait;
    time_t	ping;
    int	smax;
    time_t ttl;
    time_t timeout;

    /* part updated in httpd */
    int id;                   /* id in table and worker id */
    time_t updatetimelb; /* time of last update of the lbstatus value */
    int num_failure_idle;    /* number of time the cping/cpong failed while calculating the lbstatus value */
    int oldelected;          /* value of s->elected when calculating the lbstatus */
    time_t lastcleantry; /* time of last unsuccessful try to clean the worker in proxy part */
};
typedef struct nodemess nodemess_t; 



#define RESPONSEBUFFERSZ    1024*1024
#define SIZEOFSCORE (200 + RESPONSEBUFFERSZ) /* size of the proxy_worker_stat structure */

typedef struct {
    ngx_uint_t response_size;
    time_t response_time;    
    ngx_uint_t response_code;
    ngx_str_t request_data;
    ngx_buf_t response_buffer;
} ngx_http_upstream_health_status_t;


/* status of the node as read/store in httpd. */
struct nodeinfo {
    /* config from jboss/tomcat */
    nodemess_t mess;
    /* filled by httpd */
    time_t updatetime;   /* time of last received message */
    int offset;              /* offset to the proxy_worker_stat structure */
    u_char stat[SIZEOFSCORE];  /* to store the status */
};
typedef struct nodeinfo nodeinfo_t; 

/**
 * return the last stored in the mem structure
 * @param pointer to the shared table
 * @return APR_SUCCESS if all went well
 *
 */
ngx_int_t get_last_mem_error(mem_t *mem);

/**
 * Insert(alloc) and update a node record in the shared table
 * @param pointer to the shared table.
 * @param node node to store in the shared table.
 * @return APR_SUCCESS if all went well
 *
 */
ngx_int_t insert_update_node(mem_t *s, nodeinfo_t *node, int *id);

/**
 * read a node record from the shared table
 * @param pointer to the shared table.
 * @param node node to read from the shared table.
 * @return address of the read node or NULL if error.
 */
nodeinfo_t * read_node(mem_t *s, nodeinfo_t *node);

/**
 * get a node record from the shared table
 * @param pointer to the shared table.
 * @param node address of the node read from the shared table.
 * @return APR_SUCCESS if all went well
 */
ngx_int_t get_node(mem_t *s, nodeinfo_t **node, int ids);

/**
 * remove(free) a node record from the shared table
 * @param pointer to the shared table.
 * @param node node to remove from the shared table.
 * @return APR_SUCCESS if all went well
 */
ngx_int_t remove_node(mem_t *s, nodeinfo_t *node);

/**
 * find a node record from the shared table using JVMRoute
 * @param pointer to the shared table.
 * @param node address where the node is located in the shared table.
 * @param route JVMRoute to search
 * @return APR_SUCCESS if all went well
 */
ngx_int_t find_node(mem_t *s, nodeinfo_t **node, const u_char *route);

/*
 * get the ids for the used (not free) nodes in the table
 * @param pointer to the shared table.
 * @param ids array of int to store the used id (must be big enough).
 * @return number of node existing or -1 if error.
 */
int get_ids_used_node(mem_t *s, int *ids);

/*
 * get the size of the table (max size).
 * @param pointer to the shared table.
 * @return size of the existing table or -1 if error.
 */
int get_max_size_node(mem_t *s);

/*
 * get the version of the table (each update of the table changes version)
 * @param pointer to the shared table.
 * @return version the actual version in the table.
 */
unsigned int get_version_node(mem_t *s);

/**
 * attach to the shared node table
 * @param name of an existing shared table.
 * @param address to store the size of the shared table.
 * @param p pool to use for allocations.
 * @return address of struct used to access the table.
 */
mem_t * get_mem_node(u_char *string, int *num, ngx_pool_t *p, slotmem_storage_method *storage);
/**
 * create a shared node table
 * @param name to use to create the table.
 * @param size of the shared table.
 * @param persist tell if the slotmem element are persistent.
 * @param p pool to use for allocations.
 * @return address of struct used to access the table.
 */
mem_t * create_mem_node(u_char *string, int *num, int persist, ngx_pool_t *p,  slotmem_storage_method *storage);
ngx_int_t init_mem_node(mem_t *ptr, u_char *string, int *num, ngx_pool_t *p);
/**
 * provider for the mod_proxy_cluster or mod_jk modules.
 */
struct node_storage_method {
/**
 * the node corresponding to the ident
 * @param ids ident of the node to read.
 * @param node address of pointer to return the node.
 * @return APR_SUCCESS if all went well
 */
ngx_int_t (* read_node)(int ids, nodeinfo_t **node);
/**
 * read the list of ident of used nodes.
 * @param ids address to store the idents.
 * @return APR_SUCCESS if all went well
 */
int (* get_ids_used_node)(int *ids);
/**
 * read the max number of nodes in the shared table
 */
int (*get_max_size_node)();
/**
 * check the nodes for modifications.
 * XXX: void *data is server_rec *s in fact.
 */
unsigned int (*worker_nodes_need_update)(void *data, ngx_pool_t *pool);
/*
 * mark that the worker node are now up to date.
 */
int (*worker_nodes_are_updated)(void *data, unsigned int version);
/*
 * Remove the node from shared memory (free the slotmem)
 */
ngx_int_t (*remove_node)(nodeinfo_t *node);
/*
 * Find the node using the JVMRoute information
 */
ngx_int_t (*find_node)(nodeinfo_t **node, const u_char *route);
/*
 * Remove the virtual hosts and contexts corresponding the node.
 */
void (*remove_host_context)(int node, ngx_pool_t *pool);
};

void sort_nodes(nodeinfo_t *nodes, int nbnodes);

ngx_http_upstream_health_status_t *get_node_upstream_status (nodeinfo_t *node);

#endif	/* NODE_H */

