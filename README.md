
Name
====

**nginx_mod_cluster_module** -  Implementation of features mod_cluster to nginx, based on the original mod_cluster. 

Description
===========

This module adds support for Nginx receive and process Mod-Cluster Management Protocol (MCMP). Main goal is dynamic 
configuration of nginx upstreams. Porting the node side of mod_cluster to other technologies beyond java.

Status
======

Still in development. Lot of hard coded and PoC code. 

Todo:

	- Add support to AJP using https://github.com/yaoweibin/nginx_ajp_module.

	- Sticky session based on URL param

	- Handle upstream weight based on MCMP Load param

	- Node remove when connection fails

	- Test all working and non working features

Features working:

	- Node/upstream dynamic configuration

	- Published context routing thru nodes

	- Sticky session based on cookie param



Usage
=====

Installation:

./configure --with-cc-opt=-O  --add-module=/path/to/nginx_mod_cluster_module/advertise/ --add-module=/path/to/nginx_mod_cluster_module/manager/

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

This software is distributed under the terms of the FSF Lesser Gnu Public License (see [lgpl.txt](lgpl.txt)).
