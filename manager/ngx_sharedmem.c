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

/* Memory handler for a shared memory divided in slot.
 * This one uses shared memory.
 */
#define CORE_PRIVATE

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include  "../include/slotmem.h"
#include "sharedmem_util.h"

/* make sure the shared memory is cleaned */
static ngx_int_t initialize_cleanup(ngx_pool_t *p, ngx_pool_t *plog, ngx_pool_t *ptemp) {
  
    sharedmem_initialize_cleanup(p);
    return NGX_OK;
}
void *xxinitialize_cleanup = initialize_cleanup;

/* XXX: The global pool is clean up upon graceful restart,
 * that is to allow the resize the shared memory area using a graceful start
 * No sure that is a very good idea...
 */
static ngx_int_t pre_config(ngx_pool_t *p, ngx_pool_t *plog, ngx_pool_t *ptemp) {
    
    ngx_pool_t *global_pool;
    
    global_pool = ngx_create_pool(1024, p->log);
    if (!global_pool) {
        ngx_log_error(NGX_LOG_CRIT, p->log, 0, "Fatal error: unable to create global pool for shared slotmem");
        return NGX_ERROR;
    }
    mem_getstorage(global_pool, "");
    return NGX_OK;
}
void *xxpre_config = pre_config;

/*
 * Create the mutex of the insert/remove logic
 */
static void child_init(ngx_pool_t *p) { 
   
    sharedmem_initialize_child(p);
}
 void *xxchild_init = child_init;
   