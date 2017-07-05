# ngx_http_access_udpxy_module 

A Nginx module to restrict access to a resource on a udpxy UDP-to-HTTP multicast traffic relay daemon.
Based on [http_access](http://nginx.org/en/docs/http/ngx_http_access_module.html) module which allows limiting access to certain client addresses in addition to destination udpxy address for a specific user with basic/digest authentication.
It needs working [http_auth_basic](http://nginx.org/en/docs/http/ngx_http_auth_basic_module.html) or [http_auth_digest](https://www.nginx.com/resources/wiki/modules/auth_digest/) module to provide user name.

**nginx.conf sample**
```
  location /udp/239 {
    # digest authentication doesn't work with VLC
    auth_basic "authorization needed";
    auth_basic_user_file /etc/nginx_htpasswd;
  
    allow_udpxy testuser,all,212.1.1.9;
    deny_udpxy  testuser,all,all;
  
    #           user, src_ip/mask,  dest_ip/mask    
    allow_udpxy user2,178.72.81.102,212.0.0.0/8;
    deny_udpxy  user2,178.72.81.102,212.12.1.2;
    allow_udpxy user2,178.72.82.153,212.0.0.0/8;
    deny_udpxy  user2,178.72.83.153,212.12.1.2;
    deny_udpxy  user2,all,all;
  
    proxy_set_header Authorization '';
    proxy_pass http://127.0.0.1:6001;
  }
```
