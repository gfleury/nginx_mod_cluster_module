/*
 *  mod_cluster.
 *
 *  Copyright(c) 2008 Red Hat Middleware, LLC,
 *  and individual contributors as indicated by the @authors tag.
 *  See the copyright.txt in the distribution for a
 *  full listing of individual contributors. 
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library in the file COPYING.LIB;
 *  if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 * @author Jean-Frederic Clere
 * @version $Revision$
 */

/**
 * @file  node.c
 * @brief node description Storage Module for Apache
 *
 * @defgroup MEM nodes
 * @ingroup  APACHE_MODS
 * @{
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_manager_module.h"
#include "../include/ngx_utils.h"


static mem_t * create_attach_mem_node(u_char *string, int *num, int type, ngx_pool_t *p, slotmem_storage_method *storage) {
    mem_t *ptr;
    const u_char *storename;
    ngx_int_t rv;

    ptr = ngx_pcalloc(p, sizeof(mem_t));
    if (!ptr) {
        return NULL;
    }
    ptr->storage =  storage;
    storename = ngx_pstrcat(p, string, NODEEXE, NULL); 
    if (type) {
        rv = ptr->storage->ap_slotmem_create(&ptr->slotmem, storename, sizeof(nodeinfo_t), *num, type, p, storage->cf, storage->ngx_http_module);
    } else {
        size_t size = sizeof(nodeinfo_t);
        rv = ptr->storage->ap_slotmem_attach(&ptr->slotmem, storename, &size, num, p);
    }
    if (rv != NGX_OK) {
        ptr->laststatus = rv;
        return ptr;
    }
    ptr->laststatus = NGX_OK;
    ptr->num = *num;
    ptr->p = p;
    return ptr;
}

ngx_int_t init_mem_node(mem_t *ptr, u_char *string, int *num, ngx_pool_t *p) {
    const u_char *storename;
    ngx_int_t rv;

    if (!ptr) {
        return !NGX_OK;
    }
    
    storename = ngx_pstrcat(p, string, NODEEXE, NULL);     
    rv = ptr->storage->ap_slotmem_init(&ptr->slotmem, storename, sizeof(nodeinfo_t), *num, p);
    if (rv != NGX_OK) {
        ptr->laststatus = rv;
        return !NGX_OK;
    }
    ptr->laststatus = NGX_OK;
    
    return NGX_OK;
}

/**
 * return the last stored in the mem structure
 * @param pointer to the shared table
 * @return APR_SUCCESS if all went well
 *
 */
ngx_int_t get_last_mem_error(mem_t *mem) {
    return mem->laststatus;
}


/**
 * Insert(alloc) and update a node record in the shared table
 * @param pointer to the shared table.
 * @param node node to store in the shared table.
 * @return APR_SUCCESS if all went well
 *
 */
static ngx_int_t insert_update(void* mem, void **data, int id, ngx_pool_t *pool)
{
    nodeinfo_t *in = (nodeinfo_t *)*data;
    nodeinfo_t *ou = (nodeinfo_t *)mem;
    if (ngx_strcmp(in->mess.JVMRoute, ou->mess.JVMRoute) == 0) {
        /*
         * The node information is made of several pieces:
         * Information from the cluster (nodemess_t).
         * updatetime (time of last received message).
         * offset (of the area shared with the proxy logic).
         * stat (shared area with the proxy logic we shouldn't modify it here).
         */
        memcpy(ou, in, sizeof(nodemess_t));
        ou->mess.id = id;
        ou->updatetime = time(NULL);
        ou->offset = sizeof(nodemess_t) + sizeof(time_t) + sizeof(int);
        ou->offset = NGX_ALIGN_DEFAULT(ou->offset);
        *data = ou;
        return NGX_OK;
    }
    return NGX_NONE;
}

ngx_int_t insert_update_node(mem_t *s, nodeinfo_t *node, int *id) {
    ngx_int_t rv;
    nodeinfo_t *ou;
    int ident;

    node->mess.id = 0;
    s->storage->ap_slotmem_lock(s->slotmem);
    rv = s->storage->ap_slotmem_do(s->slotmem, insert_update, &node, 1, s->p);
    if (node->mess.id != 0 && rv == NGX_OK) {
        s->storage->ap_slotmem_unlock(s->slotmem);
        *id = node->mess.id;
        return NGX_OK; /* updated */
    }
    
    /* we have to insert it */
    rv = s->storage->ap_slotmem_alloc(s->slotmem, &ident, (void **) &ou);
    if (rv != NGX_OK) {
        s->storage->ap_slotmem_unlock(s->slotmem);
        return rv;
    }
    memcpy(ou, node, sizeof(nodeinfo_t));
    ou->mess.id = ident;
    *id = ident;
    s->storage->ap_slotmem_unlock(s->slotmem);
    ou->updatetime = time(NULL);

    /* set of offset to the proxy_worker_stat */
    ou->offset = sizeof(nodemess_t) + sizeof(time_t) + sizeof(int);
    ou->offset = NGX_ALIGN_DEFAULT(ou->offset);

    /* blank the proxy status information */
    memset(&(ou->stat), '\0', SIZEOFSCORE);
       
    /* Initialize health status struct */
    ngx_http_upstream_health_status_t *response_status;
    char *pptr = (char *) ou;
    int response_offset = NGX_ALIGN_DEFAULT((sizeof(ngx_uint_t) * 2) + sizeof(time_t) + sizeof(ngx_str_t) + sizeof(ngx_buf_t));
    int request_data_offset = NGX_ALIGN_DEFAULT(1024);
    
    response_offset = NGX_ALIGN_DEFAULT(response_offset);
    
    pptr = pptr + ou->offset;
    
    response_status = (ngx_http_upstream_health_status_t *) pptr;

    pptr = pptr + response_offset;
           
    response_status->request_data.data = (u_char *) pptr;
        
    response_offset += request_data_offset;
    
    pptr = pptr + request_data_offset;

    response_status->response_buffer.start = (u_char *) pptr;
    
    response_status->response_buffer.pos = response_status->response_buffer.start;
    response_status->response_buffer.last = response_status->response_buffer.start;
    
    pptr = (pptr + ( SIZEOFSCORE - (response_offset))) - 1;
    
    response_status->response_buffer.end = (u_char *) pptr;
 
    ngx_snprintf(response_status->request_data.data, 1023, "GET / HTTP/1.0\r\nHost: %*s\r\n\r\n", ngx_strlen(ou->mess.Host), ou->mess.Host);
    response_status->request_data.len = ngx_strlen(response_status->request_data.data);

    return NGX_OK;
}

/**
 * read a node record from the shared table
 * @param pointer to the shared table.
 * @param node node to read from the shared table.
 * @return address of the read node or NULL if error.
 */
static ngx_int_t loc_read_node(void* mem, void **data, int id, ngx_pool_t *pool) {
    nodeinfo_t *in = (nodeinfo_t *)*data;
    nodeinfo_t *ou = (nodeinfo_t *)mem;
    if (ngx_strncmp(in->mess.JVMRoute, ou->mess.JVMRoute, ngx_strlen(ou->mess.JVMRoute)) == 0) {
        *data = ou;
        return NGX_OK;
    }
    return NGX_NONE;
}

nodeinfo_t * read_node(mem_t *s, nodeinfo_t *node)
{
    ngx_int_t rv;
    nodeinfo_t *ou = node;

    if (node->mess.id)
        rv = s->storage->ap_slotmem_mem(s->slotmem, node->mess.id, (void **) &ou);
    else {
        rv = s->storage->ap_slotmem_do(s->slotmem, loc_read_node, &ou, 0, s->p);
    }
    if (rv == NGX_OK)
        return ou;
    return NULL;
}

/**
 * get a node record from the shared table (using ids).
 * @param pointer to the shared table.
 * @param node address where the node is located in the shared table.
 * @param ids  in the node table.
 * @return APR_SUCCESS if all went well
 */
ngx_int_t get_node(mem_t *s, nodeinfo_t **node, int ids)
{
  return(s->storage->ap_slotmem_mem(s->slotmem, ids, (void **) node));
}

/**
 * remove(free) a node record from the shared table
 * @param pointer to the shared table.
 * @param node node to remove from the shared table.
 * @return APR_SUCCESS if all went well
 */
ngx_int_t remove_node(mem_t *s, nodeinfo_t *node)
{
    ngx_int_t rv;
    nodeinfo_t *ou = node;
    if (node->mess.id)
        rv = s->storage->ap_slotmem_free(s->slotmem, node->mess.id, node);
    else {
        /* XXX: for the moment January 2007 ap_slotmem_free only uses ident to remove */
        rv = s->storage->ap_slotmem_do(s->slotmem, loc_read_node, &ou, 0, s->p);
        if (rv == NGX_OK)
            rv = s->storage->ap_slotmem_free(s->slotmem, ou->mess.id, node);
    }
    return rv;
}

/**
 * find a node record from the shared table using JVMRoute
 * @param pointer to the shared table.
 * @param node address where the node is located in the shared table.
 * @param route JVMRoute to search
 * @return APR_SUCCESS if all went well
 */
ngx_int_t find_node(mem_t *s, nodeinfo_t **node, const u_char *route) {
    nodeinfo_t ou;
    ngx_int_t rv;

    strcpy((char *)ou.mess.JVMRoute, (char *)route);
    *node = &ou;
    rv = s->storage->ap_slotmem_do(s->slotmem, loc_read_node, node, 0, s->p);
    return rv;
}

/*
 * get the ids for the used (not free) nodes in the table
 * @param pointer to the shared table.
 * @param ids array of int to store the used id (must be big enough).
 * @return number of node existing or -1 if error.
 */
int get_ids_used_node(mem_t *s, int *ids)
{
    return (s->storage->ap_slotmem_get_used(s->slotmem, ids));
}

/*
 * read the size of the table.
 * @param pointer to the shared table.
 * @return number of node existing or -1 if error.
 */
int get_max_size_node(mem_t *s)
{
    if (s->storage == NULL)
        return 0;
    else
        return (s->storage->ap_slotmem_get_max_size(s->slotmem));
}

/*
 * read the version of the table.
 * @param pointer to the shared table.
 * @return the version of the table
 */
unsigned int get_version_node(mem_t *s)
{
    if (s->storage == NULL)
        return 0;
    else
        return (s->storage->ap_slotmem_get_version(s->slotmem));
}

/**
 * attach to the shared node table
 * @param name of an existing shared table.
 * @param address to store the size of the shared table.
 * @param p pool to use for allocations.
 * @param storage slotmem logic provider.
 * @return address of struct used to access the table.
 */
mem_t * get_mem_node(u_char *string, int *num, ngx_pool_t *p, slotmem_storage_method *storage)
{
    return(create_attach_mem_node(string, num, 0, p, storage));
}
/**
 * create a shared node table
 * @param name to use to create the table.
 * @param size of the shared table.
 * @param persist tell if the slotmem element are persistent.
 * @param p pool to use for allocations.
 * @param storage slotmem logic provider.
 * @return address of struct used to access the table.
 */
mem_t * create_mem_node(u_char *string, int *num, int persist, ngx_pool_t *p, slotmem_storage_method *storage)
{
    return(create_attach_mem_node(string, num, CREATE_SLOTMEM|persist, p, storage));
}


void sort_nodes(nodeinfo_t *nodes, int nbnodes) {
    int i;
    int changed = -1;
    if (nbnodes <=1)
        return;
    while(changed) {
        changed = 0;
        for (i=0; i<nbnodes-1; i++) {
            if (ngx_strcmp(nodes[i].mess.Domain, nodes[i+1].mess.Domain)> 0) {
                nodeinfo_t node;
                node = nodes[i+1];
                nodes[i+1] = nodes[i];
                nodes[i] = node;
                changed = -1;
            }
        }
    }
}

ngx_http_upstream_health_status_t *get_node_upstream_status (nodeinfo_t *node) {
    ngx_http_upstream_health_status_t *response_status;
    char *pptr = (char *) node;
    int response_offset = NGX_ALIGN_DEFAULT((sizeof(ngx_uint_t) * 2) + sizeof(time_t) + sizeof(ngx_str_t) + sizeof(ngx_buf_t));
    int request_data_offset = NGX_ALIGN_DEFAULT(1024);
    
    response_offset = NGX_ALIGN_DEFAULT(response_offset);
    
    pptr = pptr + node->offset;
    
    response_status = (ngx_http_upstream_health_status_t *) pptr;

    pptr = pptr + response_offset;
           
    response_status->request_data.data = (u_char *) pptr;
        
    response_offset += request_data_offset;
    
    pptr = pptr + request_data_offset;

    response_status->response_buffer.start = (u_char *) pptr;
    
    response_status->response_buffer.pos = response_status->response_buffer.start;
    response_status->response_buffer.last = response_status->response_buffer.start;
    response_status->response_buffer.end = (response_status->response_buffer.last + ( SIZEOFSCORE - (response_offset))) - 1;
      
    return response_status;
}

