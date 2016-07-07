
Name
====

**nginx_mod_cluster_module** -  Implementation of features mod_cluster to nginx, based on the original mod_cluster. Can be used to dynamic config routes/paths on nginx. A replacer for hipache. 

Description
===========

This module adds support for Nginx receive and process Mod-Cluster Management Protocol (MCMP). Main goal is dynamic 
configuration of nginx upstreams. Porting the node side of mod_cluster to other technologies beyond java.

Status
======

Lastest Nginx working version: nginx-release-1.6.3

Pre-production ready, using for test and development environments 

Todo:

	- Add support to AJP using https://github.com/yaoweibin/nginx_ajp_module.

	- Sticky session based on URL param

	- Test all working and non working features

Features working:

	- Node/upstream dynamic configuration

	- Published context routing thru nodes

	- Sticky session based on cookie param

	- Handle upstream weight based on MCMP Load param

	- Node remove when connection fails

	- Enable/Disable/Stop Contexts using ModManagerInfo interface

Usage
=====

Installation:

 - Apply nginx patch to allow MCMP methods

patch < nginx-1.5.3_parse.patch

./configure --add-module=/path/to/nginx_mod_cluster_module/advertise/ --add-module=/path/to/nginx_mod_cluster_module/manager/

Configuration:

    server {
        listen       80;
        server_name  localhost;
        ManagerBalancerName balancer-name;
        ServerAdvertise On;
        AdvertiseFrequency 5;
        AdvertiseSecurityKey seckey;
        EnableMCPMReceive;

        location /info {
                ModManagerInfo;
        }
    }


License
=======

Based on Nginx code copyrighted by Igor Sysoev, https://github.com/nginx/nginx .

Based on Mod_cluster by jfclere, https://github.com/modcluster/mod_cluster .

Based on ngx-sticky-module by Jerome Loyet, https://code.google.com/p/nginx-sticky-module .

Based on nginx-upstream-fair by Grzegorz Nosek, https://github.com/gnosek/nginx-upstream-fair . 

This software is distributed under the terms of the FSF Lesser Gnu Public License (see [lgpl.txt](lgpl.txt)).
