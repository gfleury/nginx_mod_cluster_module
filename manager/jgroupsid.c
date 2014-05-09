/*
 *  mod_cluster
 *
 *  Copyright(c) 2012 Red Hat Middleware, LLC,
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
 * @file  jgroupsid.c
 * @brief jgroupsid description Storage Module for Apache
 *
 * @defgroup MEM jgroupsids
 * @ingroup  APACHE_MODS
 * @{
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_manager_module.h"
#include "../include/ngx_utils.h"

static mem_t * create_attach_mem_jgroupsid(u_char *string, int *num, int type, ngx_pool_t *p, slotmem_storage_method *storage) {
    mem_t *ptr;
    const u_char *storename;
    ngx_int_t rv;

    ptr = ngx_pcalloc(p, sizeof(mem_t));
    if (!ptr) {
        return NULL;
    }
    ptr->storage =  storage;
    storename = ngx_pstrcat(p, string, JGROUPSIDEXE, NULL); 
    if (type)
        rv = ptr->storage->ap_slotmem_create(&ptr->slotmem, storename, sizeof(jgroupsidinfo_t), *num, type, p, storage->cf, storage->ngx_http_module);
    else {
        size_t size = sizeof(jgroupsidinfo_t);
        rv = ptr->storage->ap_slotmem_attach(&ptr->slotmem, storename, &size, num, p);
    }
    if (rv != NGX_OK) {
        return NULL;
    }
    ptr->num = *num;
    ptr->p = p;
    return ptr;
}

ngx_int_t init_mem_jgroupsid(mem_t *ptr, u_char *string, int *num, ngx_pool_t *p) {
    const u_char *storename;
    ngx_int_t rv;

    if (!ptr) {
        return !NGX_OK;
    }
    
    storename = ngx_pstrcat(p, string, JGROUPSIDEXE, NULL); 
      
    rv = ptr->storage->ap_slotmem_init(&ptr->slotmem, storename, sizeof(jgroupsidinfo_t), *num, p);
   
    if (rv != NGX_OK) {
        return !NGX_OK;
    }

    return NGX_OK;
}

/**
 * Insert(alloc) and update a jgroupsid record in the shared table
 * @param pointer to the shared table.
 * @param jgroupsid jgroupsid to store in the shared table.
 * @return APR_SUCCESS if all went well
 *
 */
static ngx_int_t insert_update(void* mem, void **data, int id, ngx_pool_t *pool)
{
    jgroupsidinfo_t *in = (jgroupsidinfo_t *)*data;
    jgroupsidinfo_t *ou = (jgroupsidinfo_t *)mem;
    if (strcmp(in->jgroupsid, ou->jgroupsid) == 0) {
        memcpy(ou, in, sizeof(jgroupsidinfo_t));
        ou->id = id;
        ou->updatetime = time(NULL);
        *data = ou;
        return NGX_OK;
    }
    return NGX_NONE;
}
ngx_int_t insert_update_jgroupsid(mem_t *s, jgroupsidinfo_t *jgroupsid)
{
    ngx_int_t rv;
    jgroupsidinfo_t *ou;
    int ident;

    jgroupsid->id = 0;
    rv = s->storage->ap_slotmem_do(s->slotmem, insert_update, &jgroupsid, 1, s->p);
    if (jgroupsid->id != 0 && rv == NGX_OK) {
        return NGX_OK; /* updated */
    }

    /* we have to insert it */
    rv = s->storage->ap_slotmem_alloc(s->slotmem, &ident, (void **) &ou);
    if (rv != NGX_OK) {
        return rv;
    }
    memcpy(ou, jgroupsid, sizeof(jgroupsidinfo_t));
    ou->id = ident;
    ou->updatetime = time(NULL);

    return NGX_OK;
}

/**
 * read a jgroupsid record from the shared table
 * @param pointer to the shared table.
 * @param jgroupsid jgroupsid to read from the shared table.
 * @return address of the read jgroupsid or NULL if error.
 */
static ngx_int_t loc_read_jgroupsid(void* mem, void **data, int id, ngx_pool_t *pool) {
    jgroupsidinfo_t *in = (jgroupsidinfo_t *)*data;
    jgroupsidinfo_t *ou = (jgroupsidinfo_t *)mem;

    if (strcmp(in->jgroupsid, ou->jgroupsid) == 0) {
        *data = ou;
        return NGX_OK;
    }
    return NGX_NONE;
}
jgroupsidinfo_t * read_jgroupsid(mem_t *s, jgroupsidinfo_t *jgroupsid)
{
    ngx_int_t rv;
    jgroupsidinfo_t *ou = jgroupsid;

    if (jgroupsid->id)
        rv = s->storage->ap_slotmem_mem(s->slotmem, jgroupsid->id, (void **) &ou);
    else {
        rv = s->storage->ap_slotmem_do(s->slotmem, loc_read_jgroupsid, &ou, 0, s->p);
    }
    if (rv == NGX_OK)
        return ou;
    return NULL;
}
/**
 * get a jgroupsid record from the shared table
 * @param pointer to the shared table.
 * @param jgroupsid address where the jgroupsid is locate in the shared table.
 * @param ids  in the jgroupsid table.
 * @return APR_SUCCESS if all went well
 */
ngx_int_t get_jgroupsid(mem_t *s, jgroupsidinfo_t **jgroupsid, int ids)
{
  return(s->storage->ap_slotmem_mem(s->slotmem, ids, (void **) jgroupsid));
}

/**
 * remove(free) a jgroupsid record from the shared table
 * @param pointer to the shared table.
 * @param jgroupsid jgroupsid to remove from the shared table.
 * @return APR_SUCCESS if all went well
 */
ngx_int_t remove_jgroupsid(mem_t *s, jgroupsidinfo_t *jgroupsid)
{
    ngx_int_t rv;
    jgroupsidinfo_t *ou = jgroupsid;
    if (jgroupsid->id)
        rv = s->storage->ap_slotmem_free(s->slotmem, jgroupsid->id, jgroupsid);
    else {
        /* XXX: for the moment January 2007 ap_slotmem_free only uses ident to remove */
        rv = s->storage->ap_slotmem_do(s->slotmem, loc_read_jgroupsid, &ou, 0, s->p);
        if (rv == NGX_OK)
            rv = s->storage->ap_slotmem_free(s->slotmem, ou->id, jgroupsid);
    }
    return rv;
}

/*
 * get the ids for the used (not free) jgroupsids in the table
 * @param pointer to the shared table.
 * @param ids array of int to store the used id (must be big enough).
 * @return number of jgroupsid existing or -1 if error.
 */
int get_ids_used_jgroupsid(mem_t *s, int *ids)
{
    return (s->storage->ap_slotmem_get_used(s->slotmem, ids));
}

/*
 * read the size of the table.
 * @param pointer to the shared table.
 * @return number of jgroupsid existing or -1 if error.
 */
int get_max_size_jgroupsid(mem_t *s)
{
    return (s->storage->ap_slotmem_get_max_size(s->slotmem));
}

/**
 * attach to the shared jgroupsid table
 * @param name of an existing shared table.
 * @param address to store the size of the shared table.
 * @param p pool to use for allocations.
 * @return address of struct used to access the table.
 */
mem_t * get_mem_jgroupsid(u_char *string, int *num, ngx_pool_t *p, slotmem_storage_method *storage) {
    return(create_attach_mem_jgroupsid(string, num, 0, p, storage));
}
/**
 * create a shared jgroupsid table
 * @param name to use to create the table.
 * @param size of the shared table.
 * @param persist tell if the slotmem element are persistent.
 * @param p pool to use for allocations.
 * @return address of struct used to access the table.
 */
mem_t * create_mem_jgroupsid(u_char *string, int *num, int persist, ngx_pool_t *p, slotmem_storage_method *storage) {
    return(create_attach_mem_jgroupsid(string, num, CREATE_SLOTMEM|persist, p, storage));
}
