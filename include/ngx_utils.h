//
//  ngx_utils.h
//  mod_cluster-nginx
//
//  Created by George Fleury on 12/04/14.
//  Copyright (c) 2014 George Fleury. All rights reserved.
//

#ifndef mod_cluster_nginx_ngx_utils_h
#define mod_cluster_nginx_ngx_utils_h

#define MOD_CLUSTER_EXPOSED_VERSION "mod_cluster/1.3.1.dev"

#define NGX_ALIGN(size, boundary) (((size) + ((boundary) - 1)) & ~((boundary) - 1))
#define NGX_ALIGN_DEFAULT(size) NGX_ALIGN(size, 8)

#define MD5_DIGESTSIZE          16
#define UUID_FORMATTED_LENGTH   36
#define RFC822_DATE_LEN         (30)

#include <inttypes.h>

u_char *ngx_pstrndup(ngx_pool_t *pool, ngx_str_t *src, size_t n);

ngx_int_t ngx_parse_addr_port(u_char **addr, u_char **scope_id, ngx_int_t *port, const u_char *str, ngx_pool_t *p);

/*
 ** Company, Microsoft, or Digital Equipment Corporation be used in
 ** advertising or publicity pertaining to distribution of the software
 ** without specific, written prior permission. Neither Open Software
 ** Foundation, Inc., Hewlett-Packard Company, Microsoft, nor Digital
 ** Equipment Corporation makes any representations about the
 ** suitability of this software for any purpose.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#if defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#endif

/* set the following to the number of 100ns ticks of the actual
 resolution of your system's clock */
#define UUIDS_PER_TICK 1024

#ifdef WIN32
#include <windows.h>
#include "missing\stdint.h"
#define snprintf _snprintf
#else

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#else
#if HAVE_STDINT_H
#include <stdint.h>
#endif
#endif

#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#if HAVE_SYS_SYSINFO_H
#include <sys/sysinfo.h>
#endif

#endif

/* system dependent call to get the current system time. Returned as
 100ns ticks since UUID epoch, but resolution may be less than
 100ns. */

#ifdef WIN32
#define I64(C) C
#else
#define I64(C) C##LL
#endif

typedef uint64_t uuid_time_t;

typedef struct {
    char nodeID[6];
} uuid_node_t;

#undef uuid_t

typedef struct {
    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_hi_and_version;
    uint8_t clock_seq_hi_and_reserved;
    uint8_t clock_seq_low;
    uint8_t node[6];
} uuid_t;

/* some forward declarations.  kind of wimpy to do that but heck, we
 are all friends here right?  raj 20081024 */
uint16_t true_random(void);



#ifdef WIN32

void get_system_time(uuid_time_t *uuid_time);

/* Sample code, not for use in production; see RFC 1750 */
void get_random_info(char seed[16]);

#else

void get_system_time(uuid_time_t *uuid_time);

/* Sample code, not for use in production; see RFC 1750 */
void get_random_info(char seed[16]);

#endif

/* true_random -- generate a crypto-quality random number.
 **This sample doesn't do that.** */
uint16_t true_random(void);

/* puid -- print a UUID */
void puid(uuid_t u);

/* snpuid -- print a UUID in the supplied buffer */
void snpuid(u_char *str, size_t size, uuid_t u);

/* get-current_time -- get time as 60-bit 100ns ticks since UUID epoch.
 Compensate for the fact that real clock resolution is
 less than 100ns. */
void get_current_time(uuid_time_t *timestamp);


/* system dependent call to get IEEE node ID.
 This sample implementation generates a random node ID. */

/* netperf mod - don't bother trying to read or write the nodeid */
void get_ieee_node_identifier(uuid_node_t *node);

/* format_uuid_v1 -- make a UUID from the timestamp, clockseq,
 and node ID */
void format_uuid_v1(uuid_t* uuid, uint16_t clock_seq,
        uuid_time_t timestamp, uuid_node_t node);

/* uuid_create -- generator a UUID */
int uuid_create(uuid_t *uuid);

void get_uuid_string(u_char *uuid_str, size_t size);

#define NGX_INT64_T_FMT             "uL"
#define NGX_TIME_C(val)             INT64_C(val)
#define NGX_TIME_T_FMT              NGX_INT64_T_FMT
#define NGX_USEC_PER_SEC            NGX_TIME_C(1000000)
#define ngx_sec_from_time(sec)      ((sec) / NGX_USEC_PER_SEC)
#define ngx_time_from_sec(sec)      ((sec) * NGX_USEC_PER_SEC)

typedef int ngx_status_t;
typedef uint64_t ngx_interval_time_t;

ngx_status_t ngx_recent_rfc822_date(u_char *outstr, time_t t, size_t len);

u_char *ngx_get_status_line(int status);

u_char *ngx_pstrcat(ngx_pool_t *a, ...);

u_char *ngx_strncat(u_char *dst, const u_char *src, register size_t n);

/*
 Null-terminated strdup ngx impl
 */
u_char *ngx_pstrdup2(ngx_pool_t *pool, ngx_str_t *src);

/*
 Null-terminated strdup ngx impl
 */
u_char *ngx_pstrdup3(ngx_pool_t *pool, const u_char *src);
u_char *ngx_pstrndup3(ngx_pool_t *pool, const u_char *src, size_t n);

typedef struct ngx_sockaddr_s {
    struct sockaddr_in addr;
    socklen_t addrlen;
    int family;
} ngx_sockaddr_t;

ngx_int_t ngx_socket_sendto(int socket, const ngx_sockaddr_t *addr, ngx_int_t flags, void *buf, size_t *len);

void fill_mip_v4(struct ip_mreq *mip, ngx_sockaddr_t *mcast, ngx_sockaddr_t *iface);

ngx_int_t ngx_do_mcast_opt(int type, int sock, char value);

ngx_int_t ngx_mcast_loopback(int *sock, char opt);

ngx_int_t ngx_mcast_hops(int *sock, char ttl);

ngx_int_t ngx_do_mcast(int type, int *sock, ngx_sockaddr_t *mcast, ngx_sockaddr_t *iface, ngx_sockaddr_t *source);

ngx_int_t ngx_mcast_join(int *sock, ngx_sockaddr_t *mcast, ngx_sockaddr_t *iface, ngx_sockaddr_t *source);

ngx_int_t ngx_mcast_leave(int *sock, ngx_sockaddr_t *mcast, ngx_sockaddr_t *iface, ngx_sockaddr_t *source);

ngx_int_t ngx_socket_bind(int *sock, const ngx_sockaddr_t *addr);

ngx_int_t ngx_socket_opt_set(int sock, int flags, int value);

ngx_int_t ngx_socket_create(int *sock, int family, int sock_type, int protocol);

ngx_int_t ngx_sockaddr_getinfo(const u_char *hostname, const u_char *servname, int family, ngx_sockaddr_t *addr);

u_char *ngx_itoa(ngx_pool_t *p, int n);

void *ngx_usleep(uint64_t t);

u_char *ngx_ltoa(ngx_pool_t *p, long n);

#define DOCTYPE_HTML_3_2 "<!DOCTYPE HTML PUBLIC \"-//W3C//" \
                            "DTD HTML 3.2 Final//EN\">\n"

#define IOBUFSIZE 8192

ngx_int_t ngx_vbprintf(ngx_buf_t *buf, const char *fmt, va_list va);

ngx_int_t ngx_bprintf(ngx_buf_t *b, const char *fmt, ...);

ngx_int_t ngx_set_content_type(ngx_http_request_t *r, ngx_str_t *ct);

ngx_int_t ngx_set_custom_header(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *value);

ngx_int_t ngx_http_send_buffer(ngx_http_request_t *r, ngx_buf_t *b, ngx_uint_t s);

ngx_int_t ngx_http_parse_header_inside_value(ngx_table_elt_t *h, ngx_str_t *name, ngx_str_t *value);

unsigned long hash(const u_char *str);

double ngx_get_milli_time();

#endif
