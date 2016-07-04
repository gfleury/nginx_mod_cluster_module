//
//  ngx_utils.h
//  mod_cluster-nginx
//
//  Created by George Fleury on 12/04/14.
//  Copyright (c) 2014 George Fleury. All rights reserved.
//

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "../include/ngx_utils.h"

 u_char *ngx_pstrndup(ngx_pool_t *pool, ngx_str_t *src, size_t n) {
    u_char *dst;

    if (src->len < n)
        return ngx_pstrdup(pool, src);

    dst = ngx_pnalloc(pool, n + 1);

    if (dst == NULL) {
        return NULL;
    }

    ngx_memcpy(dst, src->data, n);

    dst[n] = '\0';

    return dst;
}


 ngx_int_t ngx_parse_addr_port(u_char **addr, u_char **scope_id, ngx_int_t *port, const u_char *str, ngx_pool_t *p) {

    const u_char *ch, *lastchar;
    int big_port;
    size_t addrlen;

    *addr = NULL; /* assume not specified */
    *scope_id = NULL; /* assume not specified */
    *port = 0; /* assume not specified */

    /* First handle the optional port number.  That may be all that
     * is specified in the string.
     */
    ch = lastchar = str + ngx_strlen(str) - 1;
    while (ch >= str && isdigit(*ch)) {
        --ch;
    }

    if (ch < str) { /* Entire string is the port. */
        big_port = ngx_atoi((u_char *) str, ngx_strlen(str));
        if (big_port < 1 || big_port > 65535) {
            return EINVAL;
        }
        *port = big_port;
        return NGX_OK;
    }

    if (*ch == ':' && ch < lastchar) { /* host and port number specified */
        if (ch == str) { /* string starts with ':' -- bad */
            return EINVAL;
        }
        big_port = ngx_atoi((u_char *) ch + 1, ngx_strlen(ch + 1));
        if (big_port < 1 || big_port > 65535) {
            return EINVAL;
        }
        *port = big_port;
        lastchar = ch - 1;
    }

    /* now handle the hostname */
    addrlen = lastchar - str + 1;

    /* XXX we don't really have to require APR_HAVE_IPV6 for this;
     * just pass char[] for ipaddr (so we don't depend on struct in6_addr)
     * and always define APR_INET6
     */
#if NGX_HAVE_INET6
    if (*str == '[') {
        const u_char *end_bracket = memchr(str, ']', addrlen);
        struct in6_addr ipaddr;
        const u_char *scope_delim;

        if (!end_bracket || end_bracket != lastchar) {
            *port = 0;
            return EINVAL;
        }

        /* handle scope id; this is the only context where it is allowed */
        scope_delim = memchr(str, '%', addrlen);
        if (scope_delim) {
            if (scope_delim == end_bracket - 1) { /* '%' without scope id */
                *port = 0;
                return EINVAL;
            }
            addrlen = scope_delim - str - 1;
            *scope_id = apr_palloc(p, end_bracket - scope_delim);
            memcpy(*scope_id, scope_delim + 1, end_bracket - scope_delim - 1);
            (*scope_id)[end_bracket - scope_delim - 1] = '\0';
        } else {
            addrlen = addrlen - 2; /* minus 2 for '[' and ']' */
        }

        *addr = ngx_palloc(p, addrlen + 1);
        memcpy(*addr,
                str + 1,
                addrlen);
        (*addr)[addrlen] = '\0';
        if (apr_inet_pton(AF_INET6, *addr, &ipaddr) != 1) {
            *addr = NULL;
            *scope_id = NULL;
            *port = 0;
            return EINVAL;
        }
    } else
#endif
    {
        /* XXX If '%' is not a valid char in a DNS name, we *could* check
         *     for bogus scope ids first.
         */
        *addr = ngx_palloc(p, addrlen + 1);
        memcpy(*addr, str, addrlen);
        (*addr)[addrlen] = '\0';
    }
    return NGX_OK;
}

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

#undef uuid_t

/* some forward declarations.  kind of wimpy to do that but heck, we
 are all friends here right?  raj 20081024 */
 uint16_t true_random(void);



#ifdef WIN32

 void get_system_time(uuid_time_t *uuid_time) {
    ULARGE_INTEGER time;

    /* NT keeps time in FILETIME format which is 100ns ticks since
     Jan 1, 1601. UUIDs use time in 100ns ticks since Oct 15, 1582.
     The difference is 17 Days in Oct + 30 (Nov) + 31 (Dec)
     + 18 years and 5 leap days. */
    GetSystemTimeAsFileTime((FILETIME *) & time);
    time.QuadPart +=

            (unsigned __int64) (1000 * 1000 * 10) // seconds
            * (unsigned __int64) (60 * 60 * 24) // days
            * (unsigned __int64) (17 + 30 + 31 + 365 * 18 + 5); // # of days
    *uuid_time = time.QuadPart;
}

/* Sample code, not for use in production; see RFC 1750 */
 void get_random_info(char seed[16]) {
    uint16_t myrand;
    int i;

    i = 0;
    do {
        myrand = true_random();
        seed[i++] = myrand & 0xff;
        seed[i++] = myrand >> 8;
    } while (i < 14);

}

#else

 void get_system_time(uuid_time_t *uuid_time) {
    struct timeval tp;

    gettimeofday(&tp, (struct timezone *) 0);

    /* Offset between UUID formatted times and Unix formatted times.
     UUID UTC base time is October 15, 1582.
     Unix base time is January 1, 1970.*/
    *uuid_time = ((uint64_t) tp.tv_sec * 10000000)
            + ((uint64_t) tp.tv_usec * 10)
            + I64(0x01B21DD213814000);
}

/* Sample code, not for use in production; see RFC 1750 */
 void get_random_info(char seed[16]) {
    int fd;
    uint16_t myrand;
    int i;

    /* we aren't all that picky, and we would rather not block so we
     will use urandom */
    fd = open("/dev/urandom", O_RDONLY);

    if (fd != -1) {
        read(fd, seed, 16);
        close(fd);
        return;
    }

    /* ok, now what? */

    i = 0;
    do {
        myrand = true_random();
        seed[i++] = myrand & 0xff;
        seed[i++] = myrand >> 8;
    } while (i < 14);

}

#endif

/* true_random -- generate a crypto-quality random number.
 **This sample doesn't do that.** */
 uint16_t true_random(void) {
     int inited = 0;
    uuid_time_t time_now;

    if (!inited) {
        get_system_time(&time_now);
        time_now = time_now / UUIDS_PER_TICK;
        srand((unsigned int)
                (((time_now >> 32) ^ time_now) & 0xffffffff));
        inited = 1;
    }

    return (uint16_t) rand();
}

/* puid -- print a UUID */
void puid(uuid_t u) {
    int i;

    printf("%8.8x-%4.4x-%4.4x-%2.2x%2.2x-", u.time_low, u.time_mid,
            u.time_hi_and_version, u.clock_seq_hi_and_reserved,
            u.clock_seq_low);
    for (i = 0; i < 6; i++)
        printf("%2.2x", u.node[i]);
    printf("\n");
}

/* snpuid -- print a UUID in the supplied buffer */
void snpuid(u_char *str, size_t size, uuid_t u) {
    int i;
    char *tmp = (char *) str;

    if (size < 38) {
        snprintf(tmp, size, "%s", "uuid string too small");
        return;
    }

    /* perhaps this is a trifle optimistic but what the heck */
    sprintf(tmp,
            "%8.8x-%4.4x-%4.4x-%2.2x%2.2x-",
            u.time_low,
            u.time_mid,
            u.time_hi_and_version,
            u.clock_seq_hi_and_reserved,
            u.clock_seq_low);
    tmp += 24;
    for (i = 0; i < 6; i++) {
        sprintf(tmp, "%2.2x", u.node[i]);
        tmp += 2;
    }
    *tmp = 0;

}

/* get-current_time -- get time as 60-bit 100ns ticks since UUID epoch.
 Compensate for the fact that real clock resolution is
 less than 100ns. */
 void get_current_time(uuid_time_t *timestamp) {
     int inited = 0;
     uuid_time_t time_last = 0;
     uint16_t uuids_this_tick;
    uuid_time_t time_now;

    if (!inited) {
        get_system_time(&time_now);
        uuids_this_tick = UUIDS_PER_TICK;
        inited = 1;
    }

    for (;;) {
        get_system_time(&time_now);

        /* if clock reading changed since last UUID generated, */
        if (time_last != time_now) {
            /* reset count of uuids gen'd with this clock reading */
            uuids_this_tick = 0;
            time_last = time_now;
            break;
        }
        if (uuids_this_tick < UUIDS_PER_TICK) {
            uuids_this_tick++;
            break;
        }
        /* going too fast for our clock; spin */
    }
    /* add the count of uuids to low order bits of the clock reading */
    *timestamp = time_now + uuids_this_tick;
}


/* system dependent call to get IEEE node ID.
 This sample implementation generates a random node ID. */

/* netperf mod - don't bother trying to read or write the nodeid */
 void get_ieee_node_identifier(uuid_node_t *node) {
     int inited = 0;
     uuid_node_t saved_node;
    char seed[16];

    if (!inited) {
        get_random_info(seed);
        seed[0] |= 0x01;
        memcpy(&saved_node, seed, sizeof saved_node);
    }
    inited = 1;

    *node = saved_node;
}

/* format_uuid_v1 -- make a UUID from the timestamp, clockseq,
 and node ID */
 void format_uuid_v1(uuid_t* uuid, uint16_t clock_seq,
        uuid_time_t timestamp, uuid_node_t node) {
    /* Construct a version 1 uuid with the information we've gathered
     plus a few constants. */
    uuid->time_low = (unsigned long) (timestamp & 0xFFFFFFFF);
    uuid->time_mid = (unsigned short) ((timestamp >> 32) & 0xFFFF);
    uuid->time_hi_and_version =
            (unsigned short) ((timestamp >> 48) & 0x0FFF);
    uuid->time_hi_and_version |= (1 << 12);
    uuid->clock_seq_low = clock_seq & 0xFF;
    uuid->clock_seq_hi_and_reserved = (clock_seq & 0x3F00) >> 8;
    uuid->clock_seq_hi_and_reserved |= 0x80;
    memcpy(&uuid->node, &node, sizeof uuid->node);
}

/* uuid_create -- generator a UUID */
int uuid_create(uuid_t *uuid) {
    uuid_time_t timestamp;
    uint16_t clockseq;
    uuid_node_t node;

    /* get time, node ID, saved state from non-volatile storage */
    get_current_time(&timestamp);
    get_ieee_node_identifier(&node);

    /* for us clockseq is always to be random as we have no state */
    clockseq = true_random();

    /* stuff fields into the UUID */
    format_uuid_v1(uuid, clockseq, timestamp, node);
    return 1;
}

 void get_uuid_string(u_char *uuid_str, size_t size) {
    uuid_t u;

    uuid_create(&u);
    snpuid(uuid_str, size, u);

    return;
}

#define NGX_INT64_T_FMT             "uL"
#define NGX_TIME_C(val)             INT64_C(val)
#define NGX_TIME_T_FMT              NGX_INT64_T_FMT
#define NGX_USEC_PER_SEC            NGX_TIME_C(1000000)
#define ngx_time_from_sec(sec)      ((sec) * NGX_USEC_PER_SEC)
#define ngx_sec_from_time(sec)      ((sec) / NGX_USEC_PER_SEC)

 ngx_status_t ngx_recent_rfc822_date(u_char *outstr, time_t t, size_t len) {
    struct tm *tmp;

    tmp = gmtime(&t);
    if (tmp == NULL) {
        return NGX_ERROR;
    }

    if (strftime((char *) outstr, len, "%a, %d %b %Y %T %Z", tmp) == 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

 ngx_str_t ngx_http_status_lines[] = {

    ngx_string("200 OK"),
    ngx_string("201 Created"),
    ngx_string("202 Accepted"),
    ngx_null_string, /* "203 Non-Authoritative Information" */
    ngx_string("204 No Content"),
    ngx_null_string, /* "205 Reset Content" */
    ngx_string("206 Partial Content"),

    /* ngx_null_string, */ /* "207 Multi-Status" */

#define NGX_HTTP_LAST_2XX  207
#define NGX_HTTP_OFF_3XX   (NGX_HTTP_LAST_2XX - 200)

    /* ngx_null_string, */ /* "300 Multiple Choices" */

    ngx_string("301 Moved Permanently"),
    ngx_string("302 Moved Temporarily"),
    ngx_string("303 See Other"),
    ngx_string("304 Not Modified"),
    ngx_null_string, /* "305 Use Proxy" */
    ngx_null_string, /* "306 unused" */
    ngx_string("307 Temporary Redirect"),

#define NGX_HTTP_LAST_3XX  308
#define NGX_HTTP_OFF_4XX   (NGX_HTTP_LAST_3XX - 301 + NGX_HTTP_OFF_3XX)

    ngx_string("400 Bad Request"),
    ngx_string("401 Unauthorized"),
    ngx_string("402 Payment Required"),
    ngx_string("403 Forbidden"),
    ngx_string("404 Not Found"),
    ngx_string("405 Not Allowed"),
    ngx_string("406 Not Acceptable"),
    ngx_null_string, /* "407 Proxy Authentication Required" */
    ngx_string("408 Request Time-out"),
    ngx_string("409 Conflict"),
    ngx_string("410 Gone"),
    ngx_string("411 Length Required"),
    ngx_string("412 Precondition Failed"),
    ngx_string("413 Request Entity Too Large"),
    ngx_string("414 Request-URI Too Large"),
    ngx_string("415 Unsupported Media Type"),
    ngx_string("416 Requested Range Not Satisfiable"),

    /* ngx_null_string, */ /* "417 Expectation Failed" */
    /* ngx_null_string, */ /* "418 unused" */
    /* ngx_null_string, */ /* "419 unused" */
    /* ngx_null_string, */ /* "420 unused" */
    /* ngx_null_string, */ /* "421 unused" */
    /* ngx_null_string, */ /* "422 Unprocessable Entity" */
    /* ngx_null_string, */ /* "423 Locked" */
    /* ngx_null_string, */ /* "424 Failed Dependency" */

#define NGX_HTTP_LAST_4XX  417
#define NGX_HTTP_OFF_5XX   (NGX_HTTP_LAST_4XX - 400 + NGX_HTTP_OFF_4XX)

    ngx_string("500 Internal Server Error"),
    ngx_string("501 Not Implemented"),
    ngx_string("502 Bad Gateway"),
    ngx_string("503 Service Temporarily Unavailable"),
    ngx_string("504 Gateway Time-out"),

    ngx_null_string, /* "505 HTTP Version Not Supported" */
    ngx_null_string, /* "506 Variant Also Negotiates" */
    ngx_string("507 Insufficient Storage"),
    /* ngx_null_string, */ /* "508 unused" */
    /* ngx_null_string, */ /* "509 unused" */
    /* ngx_null_string, */ /* "510 Not Extended" */

#define NGX_HTTP_LAST_5XX  508

};

 u_char *ngx_get_status_line(int status) {

    u_char *ret = NULL;

    if (status >= NGX_HTTP_OK
            && status < NGX_HTTP_LAST_2XX) {
        /* 2XX */
        status -= NGX_HTTP_OK;
        ret = ngx_http_status_lines[status].data;

    } else if (status >= NGX_HTTP_MOVED_PERMANENTLY
            && status < NGX_HTTP_LAST_3XX) {
        /* 3XX */
        status = status - NGX_HTTP_MOVED_PERMANENTLY + NGX_HTTP_OFF_3XX;
        ret = ngx_http_status_lines[status].data;

    } else if (status >= NGX_HTTP_BAD_REQUEST
            && status < NGX_HTTP_LAST_4XX) {
        /* 4XX */
        status = status - NGX_HTTP_BAD_REQUEST + NGX_HTTP_OFF_4XX;
        ret = ngx_http_status_lines[status].data;

    } else if (status >= NGX_HTTP_INTERNAL_SERVER_ERROR
            && status < NGX_HTTP_LAST_5XX) {
        /* 5XX */
        status = status - NGX_HTTP_INTERNAL_SERVER_ERROR + NGX_HTTP_OFF_5XX;
        ret = ngx_http_status_lines[status].data;

    }

    if (ret == NULL) {
        status = 500;
        status = status - NGX_HTTP_INTERNAL_SERVER_ERROR + NGX_HTTP_OFF_5XX;
        ret = ngx_http_status_lines[status].data;
    }

    return ret;
}

 u_char *ngx_pstrcat(ngx_pool_t *a, ...) {
    u_char *cp, *argp, *res;
    size_t saved_lengths[6];
    int nargs = 0;

    /* Pass one --- find length of required string */

    size_t len = 0;
    va_list adummy;

    va_start(adummy, a);

    while ((cp = va_arg(adummy, u_char *)) != NULL) {
        size_t cplen = ngx_strlen(cp);
        if (nargs < 6) {
            saved_lengths[nargs++] = cplen;
        }
        len += cplen;
    }

    va_end(adummy);

    /* Allocate the required string */

    res = (u_char *) ngx_palloc(a, len + 1);
    cp = res;

    /* Pass two --- copy the argument strings into the result space */

    va_start(adummy, a);

    nargs = 0;
    while ((argp = va_arg(adummy, u_char *)) != NULL) {
        if (nargs < 6) {
            len = saved_lengths[nargs++];
        } else {
            len = ngx_strlen(argp);
        }

        memcpy(cp, argp, len);
        cp += len;
    }

    va_end(adummy);

    /* Return the result string */

    *cp = '\0';

    return res;

}

 u_char *ngx_strncat(u_char *dst, const u_char *src, register size_t n) {
    if (n != 0) {
        register u_char *d = dst;
        register const u_char *s = src;

        while (*d != 0)
            d++;
        do {
            if ((*d = *s++) == 0)
                break;
            d++;
        } while (--n != 0);
        *d = 0;
    }
    return (dst);
}

/*
 Null-terminated strdup ngx impl
 */
 u_char *ngx_pstrdup2(ngx_pool_t *pool, ngx_str_t *src) {
    u_char *dst;
    size_t l = src->len + 1;

    dst = ngx_pnalloc(pool, l);
    if (dst == NULL) {
        return NULL;
    }

    ngx_memcpy(dst, src->data, l);

    /* force null-char */
    dst[l] = '\0';

    return dst;
}

/*
 Null-terminated strdup ngx impl
 */
 u_char *ngx_pstrdup3(ngx_pool_t *pool, const u_char *src) {
    u_char *dst;
    size_t l = ngx_strlen(src) + 1;

    dst = ngx_pnalloc(pool, l);
    if (dst == NULL) {
        return NULL;
    }

    ngx_memcpy(dst, src, l);

    /* force null-char */
    dst[l] = '\0';

    return dst;
}
 
 u_char *ngx_pstrndup3(ngx_pool_t *pool, const u_char *src, size_t n) {
    u_char *dst;
    size_t l = ngx_strlen(src);

    if (l < n)
        return ngx_pstrdup3(pool, src);
    
    dst = ngx_pnalloc(pool, n+1);
    if (dst == NULL) {
        return NULL;
    }

    ngx_memcpy(dst, src, n);

    /* force null-char */
    dst[n] = '\0';

    return dst;
}

 ngx_int_t ngx_socket_sendto(int socket, const ngx_sockaddr_t *addr, ngx_int_t flags, void *buf, size_t *len) {
    return sendto(socket, buf, *len, flags, &addr->addr, addr->addrlen);
}

 void fill_mip_v4(struct ip_mreq *mip, ngx_sockaddr_t *mcast, ngx_sockaddr_t *iface) {
    mip->imr_multiaddr = mcast->addr.sin_addr;
    if (iface == NULL) {
        mip->imr_interface.s_addr = INADDR_ANY;
    } else {
        mip->imr_interface = iface->addr.sin_addr;
    }
}

 ngx_int_t ngx_do_mcast_opt(int type, int *sock, char value) {
    ngx_int_t rv = NGX_OK;

    if (setsockopt(*sock, IPPROTO_IP, type, (const void *) &value, sizeof (value)) == -1) {
        rv = errno;
    }

    return rv;
}

 ngx_int_t ngx_mcast_loopback(int *sock, char opt) {
    return ngx_do_mcast_opt(IP_MULTICAST_LOOP, sock, opt);
}

 ngx_int_t ngx_mcast_hops(int *sock, char ttl) {
    return ngx_do_mcast_opt(IP_MULTICAST_TTL, sock, ttl);
}

 ngx_int_t ngx_do_mcast(int type, int *sock, ngx_sockaddr_t *mcast, ngx_sockaddr_t *iface, ngx_sockaddr_t *source) {

    struct ip_mreq mip4;
    ngx_int_t rv = NGX_OK;

#ifdef GROUP_FILTER_SIZE
    struct group_source_req mip;
    int ip_proto;
#endif

    if (source != NULL) {
#ifdef GROUP_FILTER_SIZE
        ip_proto = IPPROTO_IP;

        if (type == IP_ADD_MEMBERSHIP)
            type = MCAST_JOIN_SOURCE_GROUP;
        else if (type == IP_DROP_MEMBERSHIP)
            type = MCAST_LEAVE_SOURCE_GROUP;

        mip.gsr_interface = 0; // fix-me, source interface lookup
        memcpy(&mip.gsr_group, &mcast->addr, sizeof (mip.gsr_group));
        memcpy(&mip.gsr_source, &source->addr, sizeof (mip.gsr_source));

        if (setsockopt(*sock, ip_proto, type, (const void *) &mip, sizeof (mip)) == -1) {
            rv = errno;
        }

#endif
    } else {

        fill_mip_v4(&mip4, mcast, iface);

        if (setsockopt(*sock, IPPROTO_IP, type, (const void *) &mip4, sizeof (mip4)) == -1) {
            rv = errno;
        }
    }
    return rv;

}

 ngx_int_t ngx_mcast_join(int *sock, ngx_sockaddr_t *mcast, ngx_sockaddr_t *iface, ngx_sockaddr_t *source) {
    return ngx_do_mcast(IP_ADD_MEMBERSHIP, sock, mcast, iface, source);
}

 ngx_int_t ngx_mcast_leave(int *sock, ngx_sockaddr_t *mcast, ngx_sockaddr_t *iface, ngx_sockaddr_t *source) {
    return ngx_do_mcast(IP_DROP_MEMBERSHIP, sock, mcast, iface, source);
}

 ngx_int_t ngx_socket_bind(int *sock, const ngx_sockaddr_t *addr) {

    if (bind(*sock, (struct sockaddr *) &addr->addr, addr->addrlen) == -1) {
        return errno;
    }

    return NGX_OK;
}

 ngx_int_t ngx_socket_opt_set(int sock, int flags, int value) {

    int one;

    if (value)
        one = 1;
    else
        one = 0;

    if (setsockopt(sock, SOL_SOCKET, flags, (void *) &one, sizeof (int)) == -1) {
        return errno;
    }

    return NGX_OK;
}

 ngx_int_t ngx_socket_create(int *sock, int family, int sock_type, int protocol) {

    int flags = 0;
#ifdef HAVE_SOCK_CLOEXEC
    flags |= SOCK_CLOEXEC;
#endif

    *sock = socket(family, sock_type | flags, protocol);

    if (*sock < 0) {
        return errno;
    }

#ifndef HAVE_SOCK_CLOEXEC
    {
        int flags;

        if ((flags = fcntl(*sock, F_GETFD)) == -1) {
            close(*sock);
            *sock = -1;
            return errno;
        }

        flags |= FD_CLOEXEC;
        if (fcntl(*sock, F_SETFD, flags) == -1) {
            close(*sock);
            *sock = -1;
            return errno;
        }
    }
#endif

    return NGX_OK;
}

 ngx_int_t ngx_sockaddr_getinfo(const u_char *hostname, const u_char *servname, int family, ngx_sockaddr_t *addr) {

    struct addrinfo hints, *result;
    int error;

    memset(&hints, 0, sizeof (hints));

    hints.ai_family = family == 0 ? AF_UNSPEC : family;

    hints.ai_socktype = SOCK_STREAM;
    if (hostname == NULL) {
        hints.ai_flags |= AI_PASSIVE;
    }

    hints.ai_protocol = 0; /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    error = getaddrinfo((char *) hostname, (char *) servname, &hints, &result);

    if (error != 0) {
        return error;
    }

    memcpy(&addr->addr, result->ai_addr, result->ai_addrlen);
    addr->family = result->ai_family;
    addr->addrlen = result->ai_addrlen;

    freeaddrinfo(result);

    return NGX_OK;

}

 u_char *ngx_itoa(ngx_pool_t *p, int n) {
    const int BUFFER_SIZE = sizeof (int) * 3 + 2;
    u_char *buf = ngx_palloc(p, BUFFER_SIZE);
    u_char *start = buf + BUFFER_SIZE - 1;
    int negative;
    if (n < 0) {
        negative = 1;
        n = -n;
    } else {
        negative = 0;
    }
    *start = 0;
    do {
        *--start = '0' + (n % 10);
        n /= 10;
    } while (n);
    if (negative) {
        *--start = '-';
    }
    return start;
}

 void *ngx_usleep(uint64_t t) {

    struct timeval tv;
    tv.tv_usec = t % NGX_USEC_PER_SEC;
    tv.tv_sec = t / NGX_USEC_PER_SEC;

    //sleep (tv.tv_sec);
    //usleep (tv.tv_usec);

    select(0, NULL, NULL, NULL, &tv);

    return NULL;
}

 u_char *ngx_ltoa(ngx_pool_t *p, long n) {
    const int BUFFER_SIZE = sizeof (long) * 3 + 2;
    u_char *buf = ngx_palloc(p, BUFFER_SIZE);
    u_char *start = buf + BUFFER_SIZE - 1;
    int negative;
    if (n < 0) {
        negative = 1;
        n = -n;
    } else {
        negative = 0;
    }
    *start = 0;
    do {
        *--start = (u_char) ('0' + (n % 10));
        n /= 10;
    } while (n);
    if (negative) {
        *--start = '-';
    }
    return start;
}

#define DOCTYPE_HTML_3_2 "<!DOCTYPE HTML PUBLIC \"-//W3C//" \
                            "DTD HTML 3.2 Final//EN\">\n"

#define IOBUFSIZE 8192

 ngx_int_t ngx_vbprintf(ngx_buf_t *buf, const char *fmt, va_list va) {

    u_char *lastpos;
    size_t written;
    u_char vrprintf_buf[IOBUFSIZE];


    lastpos = ngx_vsnprintf(vrprintf_buf, IOBUFSIZE, fmt, va);

    written = lastpos - vrprintf_buf;
    
    if (written > 0 && written <= IOBUFSIZE) {

        buf->last = ngx_cpymem(buf->last, vrprintf_buf, written);

    } else if (written > IOBUFSIZE)
        written = -1;

    return written;
}

 ngx_int_t ngx_bprintf(ngx_buf_t *b, const char *fmt, ...) {
    va_list va;
    int n;

    va_start(va, fmt);
    n = ngx_vbprintf(b, fmt, va);
    va_end(va);

    return n;
}

 ngx_int_t ngx_set_content_type (ngx_http_request_t *r, ngx_str_t *ct) { 
    r->headers_out.content_type_len = ct->len;
    r->headers_out.content_type = *ct;
    r->headers_out.content_type_hash = 1;
    return NGX_OK;
}

ngx_int_t ngx_set_custom_header(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *value) {
    ngx_table_elt_t   *h;
 
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
 
    h->key = *key;
    h->value = *value;
    h->hash = 1;
 
    return NGX_OK;
}

ngx_int_t ngx_http_send_buffer(ngx_http_request_t *r, ngx_buf_t *b, ngx_uint_t s) {
    ngx_chain_t out;
    ngx_int_t rc;

    if (b) {
        if (r == r->main) {
            b->last_buf = 1;
        }

        b->last_in_chain = 1;

        out.buf = b;
        out.next = NULL;

        r->headers_out.content_length_n = b->last - b->start;
    } else
        r->headers_out.content_length_n = 0;
    
    r->headers_out.status = s;
    
    if (r->headers_out.content_length_n <= 0) {
        r->header_only = 1;
        //r->keepalive = 0;
    }
    
    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) 
        return rc;
    
        
    
    return ngx_http_output_filter(r, &out);
}

ngx_int_t ngx_http_parse_header_inside_value (ngx_table_elt_t *h, ngx_str_t *name, ngx_str_t *value) {
    ngx_uint_t rv = NGX_OK;
    u_char *start, *last, *end, ch;

    start = h->value.data;
    end = h->value.data + h->value.len;

    while (start < end) {

        if (ngx_strncasecmp(start, name->data, name->len) != 0) {
            goto skip;
        }

        for (start += name->len; start < end && *start == ' '; start++) {
            /* void */
        }

        if (value == NULL) {
            if (start == end || *start == ',') {
                return rv;
            }

            goto skip;
        }

        if (start == end || *start++ != '=') {
            /* the invalid header value */
            goto skip;
        }

        while (start < end && *start == ' ') {
            start++;
        }

        for (last = start; last < end && *last != ';'; last++) {
            /* void */
        }

        value->len = last - start;
        value->data = start;

        return rv;

skip:

        while (start < end) {
            ch = *start++;
            if (ch == ';' || ch == ',') {
                break;
            }
        }

        while (start < end && *start == ' ') {
            start++;
        }
    }

    return NGX_DECLINED;

}

unsigned long hash(const u_char *str) {
	unsigned long hash = 5381;
	int c;

	while ((c = *str++)) {
		hash = ((hash << 5) + hash) + c;
	}
	return hash;
}

double ngx_get_milli_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);

    double time_in_mill = (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;
    
    return time_in_mill;
}