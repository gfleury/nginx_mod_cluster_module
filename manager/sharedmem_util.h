/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Memory handler for a shared memory divided in slot.
 * This one uses shared memory.
 */

slotmem_storage_method *sharedmem_getstorage();
ngx_int_t sharedmem_initialize_child(ngx_pool_t *p);

#define 	NGX_FLOCK_SHARED   1
#define 	NGX_FLOCK_EXCLUSIVE   2
#define 	NGX_FLOCK_TYPEMASK   0x000F
#define 	NGX_FLOCK_NONBLOCK   0x0010

#define     ENOSHMAVAIL 20015
#define     ESHMTOOSMAL 20016

ngx_int_t ngx_file_lock(ngx_file_t *thefile, int type);

ngx_int_t ngx_file_unlock(ngx_file_t *thefile);

ngx_int_t sharedmem_initialize_child(ngx_pool_t *p);