/* 
 * File:   mod_clustersize.h
 * Author: georgefleury
 *
 * Created on April 17, 2014, 11:14 PM
 */

#ifndef MOD_CLUSTERSIZE_H
#define	MOD_CLUSTERSIZE_H

/* For host.h */
#define HOSTALIASZ 100

/* For context.h */
#define CONTEXTSZ 80

/* For node.h */
#define BALANCERSZ 40
#define JVMROUTESZ 80
#define DOMAINNDSZ 20
#define HOSTNODESZ 64
#define PORTNODESZ 7
#define SCHEMENDSZ 6

/* For balancer.h */
#define COOKNAMESZ 30
#define PATHNAMESZ 30

/* For sessionid.h */
#define SESSIONIDSZ 128

/* For jgroupsid.h */
#define JGROUPSIDSZ   80
#define JGROUPSDATASZ 200

#endif	/* MOD_CLUSTERSIZE_H */

