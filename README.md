# Turnout

Let's suppose for some reason your ISP is incapable to grant you reliable access to some websites. In such case, many of us ended up with a dual-connection plan.

A main connection provided by the ISP as is, is complemented by a second connection circumventing the weakness of the first. The second route is usually metered, and accessible via a SOCKS5 interface.

Turnout is aimed to give users smooth browsing experience while minimizing the traffic ($$) incurred on the metered connection, by doing smart routing in the background.

```
User ------ Router ---(ISP)---- Route 1 (default unreliable route)
               |
               -----(SOCKS5)--- Route 2 (metered reliable route)
```

### Conventional routing plans

- Geographic IP list

  Route domestic traffic via route 1 and foreign traffic via route 2.
  
  ✔ Simple and easy to maintain
  
  ❌ High traffic on route 2 (expensive)
  
  ❌ Unnecessary and inefficient on non-blocked sites

- Domain list (e.g. g\**list)

  Keep a long list containing every site that needs special care.
  
  ✔ Save traffic as compared to geographic plan
  
  ❌ Need maintenance to keep the list up to date
  
  ❌ Impossible to cover every site
  
  ❌ There is no "one size fits all"
  
- Smart routing (e.g. COW)

  Only use route 2 if the site is blocked on route 1.
  
  ✔ Save traffic to minimum
  
  ✔ No need to keep any list
  
  ❌ Need learning at startup
  
  ❌ No transparent proxy (not supposed to be used on routers)
  
  ❌ Direct route can sometimes be very slow
  
- Turnout

  Smart routing like COW but more efficient and works great on routers.
  
  ✔ Save traffic to minimum
  
  ✔ No list
  
  ✔ No learning curve
  
  ✔ Work as both HTTP proxy (all platforms) and transparent proxy (Linux only)
  
  ✔ Slow connection detection
  
  ✔ Sniff hostnames and use in route 2 for better speed (transparent proxy mode)
  
  ✔ Live with bogus DNS results from ISP
  
  ❌ No UDP, no DNS and tunneling tools integrated, just do routing
  
### Usage

- Transparent proxy (Linux only)

  Both TPROXY (use -t option) and REDIRECT modes are supported. You need to redirect the traffic using iptables. TPROXY mode is faster then REDIRECT but TPROXY kernel module may be missing on some old systems.
  
  This command starts a transparent proxy at port 2222 and sets 127.0.0.1:1080 as upstream SOCKS5 proxy. Connections with download speed less than 100 kB/s will be added to slow list and routed via route 2 on next connection.
  
  ```
  turnout -b 0.0.0.0:2222 -s 127.0.0.1:1080 -t -slow 100
  ```
  
- HTTP proxy

  This command starts an HTTP proxy at localhost's port 8080 and sets 127.0.0.1:1080 as upstream SOCKS5 proxy. Connections with download speed less than 100 kB/s will be added to slow list and routed via route 2 on next connection.
  
  ```
  turnout -h 127.0.0.1:8080 -s 127.0.0.1:1080 -slow 100
  ```
  
### Known issues

  - Linux open files limit
  
    The default open files limit on Linux is 1024. You can check it by running `ulimit -n`.
    
    By the proxy nature Turnout uses a large number of connections and is hence very likely to reach the limit. You are strongly advised to increase that number. 
    For example this command sets limit to 10000 and starts Turnout if successful.
    
    ```
    ulimit -n 10000 && turnout -b 0.0.0.0:2222 -s 127.0.0.1:1080 -t
    ```
    
  - Unexpected closure of TLS connections
  
    In some circumstances, the server (or some intermediary) may cut the connection before it should close. 
    Due to TLS connections' encrypted nature, Turnout may not be able to tell if the closure is normal and thus cannot identify the blockage.
    
### Credits

  Turnout is similar in idea to but not based on the code of COW. Therefore please do not expect the same behavior.
  
  Turnout has used these external packages, either directly or by modifying their code:
  
  golang.org/x/crypto by Google
  
  golang.org/x/net by Google
  
  Avege by missdear (only to obtain original destinations)
