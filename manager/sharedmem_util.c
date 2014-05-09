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

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_manager_module.h"
#include "../include/ngx_utils.h"
#include "sharedmem_util.h"


#include <pthread.h>
#include <sys/shm.h>


#if APR_HAVE_UNISTD_H
#include <unistd.h>         /* for getpid() */
#endif

#if HAVE_SYS_SEM_H
#include <sys/shm.h>
#if !defined(SHM_R)
#define SHM_R 0400
#endif
#if !defined(SHM_W)
#define SHM_W 0200
#endif
#endif

/* The description of the slots to reuse the slotmem */
struct sharedslotdesc {
    size_t item_size;
    int item_num;
    unsigned int version; /* integer updated each time we make a change through the API */
};

struct ap_slotmem {
    u_char *name;
    ngx_shm_zone_t *shm;
    int *ident; /* integer table to process a fast alloc/free */
    unsigned int *version; /* address of version */
    void *base;
    size_t size;
    int num;
    ngx_pool_t *globalpool;
    ngx_file_t *global_lock; /* file used for the locks */
    struct ap_slotmem *next;
};

/* global pool and list of slotmem we are handling */
static struct ap_slotmem *globallistmem = NULL;
static ngx_pool_t *globalpool = NULL;
static pthread_mutex_t globalmutex_lock;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;

ngx_int_t unixd_set_shm_perms(const char *fname) {

    struct shmid_ds shmbuf;
    key_t shmkey;
    int shmid;

    shmkey = ftok(fname, 1);
    if (shmkey == (key_t)-1) {
        return errno;
    }
    if ((shmid = shmget(shmkey, 0, SHM_R | SHM_W)) == -1) {
        return errno;
    }

    shmbuf.shm_perm.uid  = getuid();
    shmbuf.shm_perm.gid  = getgid();

    shmbuf.shm_perm.mode = 0600;
    if (shmctl(shmid, IPC_SET, &shmbuf) == -1) {
        return errno;
    }
    return NGX_OK;
}

/*
 * Persiste the slotmem in a file
 * slotmem name and file name.
 * for example use:
 * anonymous : $server_root/logs/anonymous.slotmem
 * :module.c : $server_root/logs/module.c.slotmem
 * abs_name  : $abs_name.slotmem
 *
 */
static const u_char *store_filename(ngx_pool_t *pool, const u_char *slotmemname) {
    const u_char *storename;
    storename = ngx_pstrcat(pool, slotmemname , ".slotmem", NULL); 
    return storename;
}

static void store_slotmem(ap_slotmem_t *slotmem) {
    size_t nbytes;
    const u_char *storename;
    int fd;
    
    storename = store_filename(slotmem->globalpool, slotmem->name);
    
    fd = ngx_open_file(storename, O_CREAT | O_RDWR, NGX_FILE_OPEN, 0666);
    if (fd == NGX_INVALID_FILE && ngx_errno == EEXIST) {
        ngx_delete_file(storename);
        fd = ngx_open_file(storename, O_CREAT | O_RDWR, NGX_FILE_OPEN, 0666);
    }
    
    if (fd == NGX_INVALID_FILE) {
        return;
    }
    
    nbytes = slotmem->size * slotmem->num + sizeof(int) * (slotmem->num + 1);
    ngx_write_fd(fd, slotmem->ident, nbytes);
    ngx_close_file(fd);
}

void restore_slotmem(void *ptr, const u_char *name, size_t item_size, int item_num, ngx_pool_t *pool) {
    const u_char *storename;
    int fd;
    off_t nbytes;

    item_size = NGX_ALIGN_DEFAULT(item_size);
    nbytes = item_size * item_num + sizeof(int) * (item_num + 1);
    storename = store_filename(pool, name);
    fd = ngx_open_file(storename, O_RDWR, NGX_FILE_OPEN, 0666);;
    if (fd != NGX_INVALID_FILE) {
        struct stat st;
        if (stat((char *)storename, &st) == NGX_OK) {
            if (st.st_size == nbytes) {
                ngx_read_fd(fd, ptr, nbytes);
            } else {
                ngx_close_file(fd);
                ngx_delete_file(storename);
                return;
            }
        }
        ngx_close_file(fd);
    }
}

void cleanup_slotmem(void *param) {
    ap_slotmem_t **mem = param;

    if (*mem) {
        ap_slotmem_t *next = *mem;
        while (next) {
            store_slotmem(next);
//            apr_shm_destroy(next->shm);
            /* XXX: remove the lock file ? */
            if (next->global_lock) {
                ngx_close_file(next->global_lock->fd);
                next->global_lock = 0;
            }
            next = next->next;
        }
    }
    return;
}

static ngx_int_t ap_slotmem_do(ap_slotmem_t *mem, mc_slotmem_callback_fn_t *func, void *data, int new_version, ngx_pool_t *pool) {
    int i, j, isfree, *ident;
    char *ptr;
    ngx_int_t rv;

    if (!mem) {
        return ENOSHMAVAIL;
    }

    /* performs the func only on allocated slots! */
    ptr = mem->base;
    for (i = 1; i < mem->num+1; i++) {
        ident = mem->ident;
        isfree = 0;
        for (j=0; j<mem->num+1; j++) {
            if (ident[j] == i) {
                isfree = 1;
                break;
            }
        }
        if (!isfree) {
            rv = func((void *)ptr, data, i, pool);
            if (rv == NGX_OK) {
                if (new_version)
                   (*mem->version)++;
                return(rv);
            }
        }
        ptr = ptr + mem->size;
    }
    return NGX_NONE;
}

/* Lock the file lock (between processes) and then the mutex */
static ngx_int_t ap_slotmem_lock(ap_slotmem_t *s) {
    ngx_int_t rv;
    rv = ngx_file_lock(s->global_lock, NGX_FLOCK_EXCLUSIVE);
    if (rv != NGX_OK)
        return rv;
    rv = pthread_mutex_lock(&globalmutex_lock);
    if (rv != NGX_OK)
        ngx_file_unlock(s->global_lock);
    return rv;
}

static ngx_int_t ap_slotmem_unlock(ap_slotmem_t *s) {
    pthread_mutex_unlock(&globalmutex_lock);
    return(ngx_file_unlock(s->global_lock));
}

void globalmutex_init () {
        pthread_mutex_init(&globalmutex_lock, PTHREAD_MUTEX_DEFAULT);
}

static ngx_int_t ngx_http_manager_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data) {
    //ngx_slab_pool_t *shpool;
    //void *data_loc = NULL;
    
    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    //shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    //data_loc = ngx_slab_alloc(shpool, shm_zone->shm.size);
    //if (data_loc == NULL) {
    //    return NGX_ERROR;
    //}
    
    //shm_zone->data = data_loc;
   
    shm_zone->data = shm_zone->shm.addr;

    return NGX_OK;
}

/* Create the whole slotmem array */
static ngx_int_t ap_slotmem_create(ap_slotmem_t **new, const u_char *name, size_t item_size, int item_num, int persist, ngx_pool_t *pool, ngx_conf_t *cf, ngx_http_module_t *ngx_http_module) {
    struct sharedslotdesc desc;
    ap_slotmem_t *res;
    ap_slotmem_t *next = globallistmem;
    const u_char *fname;
    const u_char *filename;
    size_t nbytes;
    size_t dsize = NGX_ALIGN_DEFAULT(sizeof(desc));
    size_t tsize = NGX_ALIGN_DEFAULT(sizeof(int) * (item_num + 1));

    item_size = NGX_ALIGN_DEFAULT(item_size);
    nbytes = item_size * item_num + tsize + dsize;
    
    nbytes = ngx_align(nbytes, ngx_pagesize);
     
    if (nbytes < (size_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Shared Memory \"%s\" is too small, must be at least %udKiB", name, (8 * ngx_pagesize) >> 10);
        return ESHMTOOSMAL;
    }
    
    if (globalpool == NULL)
        return ENOSHMAVAIL;
    if (name) {
        fname = name;

        /* first try to attach to existing slotmem */
        if (next) {
            for (;;) {
                if (ngx_strcmp(next->name, fname) == 0) {
                    /* we already have it */
                    *new = next;
                    return NGX_OK;
                }
                if (!next->next) {
                    break;
                }
                next = next->next;
            }
        }
    } else {
        fname = (u_char *)"anonymous";
    }

    /* create the lock file and the global mutex */
    res = (ap_slotmem_t *) ngx_pcalloc(globalpool, sizeof(ap_slotmem_t));
    filename = ngx_pstrcat(pool, fname , ".lock", NULL);
    if (!res)
        return NGX_ERROR;
    res->global_lock = (ngx_file_t *) ngx_pcalloc(globalpool, sizeof(ngx_file_t));
    if (!res->global_lock)
        return NGX_ERROR;
    res->global_lock->fd = ngx_open_file(filename, O_CREAT | O_RDWR, NGX_FILE_OPEN, 0666); 
    if (res->global_lock->fd == NGX_INVALID_FILE) {
        return ngx_errno;
    }

    pthread_once(&init_once, globalmutex_init);
    /* lock for creation */
    ap_slotmem_lock(res);

    /* first try to attach to existing shared memory */
    {
        //rv = apr_shm_create(&, nbytes, fname, globalpool);
        ngx_str_t *shm_name;    
        shm_name = ngx_palloc(cf->pool, sizeof *shm_name);
        shm_name->data = (u_char *) fname;
        shm_name->len = ngx_strlen(fname);
        res->shm = ngx_shared_memory_add(cf, shm_name, nbytes, ngx_http_module);
        if (res->shm == NULL) {
            return NGX_ERROR;
        }
        res->shm->init = ngx_http_manager_init_shm_zone;
                
    }

    /* For the chained slotmem stuff */
    res->name = ngx_pstrdup3(globalpool, fname);
  
    res->size = item_size;
    res->num = item_num;
    res->globalpool = globalpool;
    res->next = NULL;
    if (globallistmem==NULL) {
        globallistmem = res;
    }
    else {
        next->next = res;
    }

    *new = res;
    ap_slotmem_unlock(res);
    return NGX_OK;
}

static ngx_int_t ap_slotmem_init(ap_slotmem_t **new, const u_char *name, size_t item_size, int item_num, ngx_pool_t *pool) {
    u_char *ptr;
    struct sharedslotdesc desc, *new_desc;
    ap_slotmem_t *res;
    const u_char *fname;
    size_t nbytes;
    int i, *ident;
    size_t dsize = NGX_ALIGN_DEFAULT(sizeof(desc));
    size_t tsize = NGX_ALIGN_DEFAULT(sizeof(int) * (item_num + 1));

    item_size = NGX_ALIGN_DEFAULT(item_size);
    nbytes = item_size * item_num + tsize + dsize;
    if (globalpool == NULL)
        return ENOSHMAVAIL;
    if (name) {
        fname = name;
    } else {
        fname = (u_char *)"anonymous";
    }

    res = *new;
    
    if (!res)
        return NGX_ERROR;
    

    pthread_once(&init_once, globalmutex_init);
    
    /* lock for creation */
    ap_slotmem_lock(res);

    /* first try to attach to existing shared memory */
    {
        if (res->shm == NULL) {
            return NGX_ERROR;
        }
                
        ptr = res->shm->shm.addr;
        desc.item_size = item_size;
        desc.item_num = item_num;
        new_desc = (struct sharedslotdesc *) ptr;
        memcpy(ptr, &desc, sizeof(desc));
        ptr = ptr +  dsize;
        /* write the idents table */
        ident = (int *) ptr;
        for (i=0; i<item_num+1; i++) {
            ident[i] = i + 1;
        }
        /* clean the slots table */
        memset(ptr + sizeof(int) * (item_num + 1), 0, item_size * item_num);
        /* try to restore the _whole_ stuff from a persisted location */
//FIX        if (persist & CREPER_SLOTMEM)
//            restore_slotmem(ptr, fname, item_size, item_num, pool);
    }

    /* For the chained slotmem stuff */
    res->ident = (int *) ptr;
    res->base = ptr + tsize;
    res->size = item_size;
    res->num = item_num;
    res->version = &(new_desc->version);
    res->globalpool = globalpool;
 
    ap_slotmem_unlock(res);
    return NGX_OK;
}

static ngx_int_t ap_slotmem_attach(ap_slotmem_t **new, const u_char *name, size_t *item_size, int *item_num, ngx_pool_t *pool) {
    u_char *ptr;
    ap_slotmem_t *res;
    ap_slotmem_t *next = globallistmem;
    struct sharedslotdesc desc;
    const u_char *fname;
    const u_char *filename;
    ngx_int_t rv;
    size_t dsize = NGX_ALIGN_DEFAULT(sizeof(desc));
    size_t tsize;

    *item_size = NGX_ALIGN_DEFAULT(*item_size);

    if (globalpool == NULL) {
        return ENOSHMAVAIL;
    }
    if (name) {
        fname = name;
    }
    else {
        return ENOSHMAVAIL;
    }

    /* first try to attach to existing slotmem */
    if (next) {
        for (;;) {
            if (ngx_strcmp(next->name, fname) == 0) {
                /* we already have it */
                *new = next;
                *item_size = next->size;
                *item_num = next->num;
                return NGX_OK;
            }
            if (!next->next)
                break;
            next = next->next;
        }
    }

    /* first try to attach to existing shared memory */
    res = (ap_slotmem_t *) ngx_pcalloc(globalpool, sizeof(ap_slotmem_t));
    rv = NGX_OK;//apr_shm_attach(&res->shm, fname, globalpool);
    if (rv != NGX_OK) {
        return rv;
    }
    /* get the corresponding lock */
    filename = ngx_pstrcat(pool, fname , ".lock", NULL);
    res->global_lock->fd = ngx_open_file(filename, O_CREAT | O_RDWR, NGX_FILE_OPEN, 0666);

    if (res->global_lock->fd == NGX_INVALID_FILE) {
        return ngx_errno;
    }

    /* Read the description of the slotmem */
    ptr = res->shm->shm.addr;
    memcpy(&desc, ptr, sizeof(desc));
    ptr = ptr + dsize;
    tsize = NGX_ALIGN_DEFAULT(sizeof(int) * (desc.item_num + 1));

    /* For the chained slotmem stuff */
    res->name = ngx_pstrdup3(globalpool, fname);
    res->ident = (int *)ptr;
    res->base = ptr + tsize;
    res->size = desc.item_size;
    res->num = desc.item_num;
    *res->version = 0;
    res->globalpool = globalpool;
    res->next = NULL;
    if (globallistmem==NULL) {
        globallistmem = res;
    }
    else {
        next->next = res;
    }

    *new = res;
    *item_size = desc.item_size;
    *item_num = desc.item_num;
    return NGX_OK;
}

static ngx_int_t ap_slotmem_mem(ap_slotmem_t *score, int id, void**mem) {

    char *ptr;
    int i;
    int *ident;

    if (!score) {
        return ENOSHMAVAIL;
    }
    if (id<0 || id>score->num) {
        return ENOSHMAVAIL;
    }

    /* Check that it is not a free slot */
    ident = score->ident;
    for (i=0; i<score->num+1; i++) {
        if (ident[i] == id)
            return NGX_NONE;
    } 

    ptr = (char *) score->base + score->size * (id - 1);
    if (!ptr) {
        return ENOSHMAVAIL;
    }
    *mem = ptr;
    return NGX_OK;
}

static ngx_int_t ap_slotmem_alloc(ap_slotmem_t *score, int *item_id, void **mem) {
    int ff;
    int *ident;
    ngx_int_t rv;
    ident = score->ident;
    ff = ident[0];
    if (ff > score->num) {
        rv = ENOMEM;
    } else {
        ident[0] = ident[ff];
        ident[ff] = 0;
        *item_id = ff;
        *mem = (char *) score->base + score->size * (ff - 1);
        (*score->version)++;
        rv = NGX_OK;
    }
    
    return rv;
}

static ngx_int_t ap_slotmem_free(ap_slotmem_t *score, int item_id, void*mem) {
    int ff;
    int *ident;
    if (item_id > score->num || item_id <=0) {
        return EINVAL;
    } else {
        ap_slotmem_lock(score);
        ident = score->ident;
        if (ident[item_id]) {
            ap_slotmem_unlock(score);
            (*score->version)++;
            return NGX_OK;
        }
        ff = ident[0];
        ident[0] = item_id;
        ident[item_id] = ff;
        ap_slotmem_unlock(score);
        (*score->version)++;
        return NGX_OK;
    }
}

static int ap_slotmem_get_used(ap_slotmem_t *score, int *ids) {
    int i, ret = 0;
    int *ident;

    ident = score->ident;
    for (i=0; i<score->num+1; i++) {
        if (ident[i] == 0) {
            *ids = i;
            ids++;
            ret++;
        }
    }
    return ret;
}

static int ap_slotmem_get_max_size(ap_slotmem_t *score) {
    if (score == NULL)
        return 0;
    return score->num;
}

static unsigned int ap_slotmem_get_version(ap_slotmem_t *score) {
    if (score == NULL)
        return 0;
    return *score->version;
}

static slotmem_storage_method storage = {
    &ap_slotmem_do,
    &ap_slotmem_create,
    &ap_slotmem_init,
    &ap_slotmem_attach,
    &ap_slotmem_mem,
    &ap_slotmem_alloc,
    &ap_slotmem_free,
    &ap_slotmem_get_used,
    &ap_slotmem_get_max_size,
    &ap_slotmem_lock,
    &ap_slotmem_unlock,
    &ap_slotmem_get_version,
    NULL, 
    NULL
};

/* make the storage usuable from outside
 * and initialise the global pool */
slotmem_storage_method *mem_getstorage(ngx_pool_t *p, char *type) {
    if (globalpool == NULL && p != NULL)
        globalpool = p;
    return(&storage);
}

/* Add the pool_clean routine */
void sharedmem_initialize_cleanup(ngx_pool_t *p) {
    ngx_pool_cleanup_t *cln;

    cln = ngx_pool_cleanup_add(p, 0);
    if (cln == NULL) {
        return;
    }

    cln->handler = cleanup_slotmem;
    cln->data = &globallistmem;

    //ngx_pool_cleanup_register(p, &globallistmem, cleanup_slotmem, ngx_pool_cleanup_null);
}

/* Create the mutex for insert/remove logic */
ngx_int_t sharedmem_initialize_child(ngx_pool_t *p) {
    return (pthread_once(&init_once, globalmutex_init));
}

ngx_int_t ngx_file_unlock(ngx_file_t *thefile) {
    int rc;

    struct flock l = {0,0,0,0,0};

    l.l_whence = SEEK_SET; /* lock from current point */
    l.l_start = 0; /* begin lock at this offset */
    l.l_len = 0; /* lock to end of file */
    l.l_type = F_UNLCK;

    /* keep trying if fcntl() gets interrupted (by a signal) */
    while ((rc = fcntl(thefile->fd, F_SETLKW, &l)) < 0
            && errno == EINTR)
        continue;

    if (rc == -1)
        return errno;

    return NGX_OK;
}

ngx_int_t ngx_file_lock(ngx_file_t *thefile, int type) {
    int rc;
    
    struct flock l = {0,0,0,0,0};
    int fc;

    l.l_whence = SEEK_SET; /* lock from current point */
    l.l_start = 0; /* begin lock at this offset */
    l.l_len = 0; /* lock to end of file */
    if ((type & NGX_FLOCK_TYPEMASK) == NGX_FLOCK_SHARED)
        l.l_type = F_RDLCK;
    else
        l.l_type = F_WRLCK;

    fc = (type & NGX_FLOCK_NONBLOCK) ? F_SETLK : F_SETLKW;

    /* keep trying if fcntl() gets interrupted (by a signal) */
    while ((rc = fcntl(thefile->fd, fc, &l)) < 0 && errno == EINTR)
        continue;

    if (rc == -1) {
        /* on some Unix boxes (e.g., Tru64), we get EACCES instead
         * of EAGAIN; we don't want APR_STATUS_IS_EAGAIN() matching EACCES
         * since that breaks other things, so fix up the retcode here
         */
        if (errno == EACCES) {
            return EAGAIN;
        }
        return errno;
    }

    return NGX_OK;
}