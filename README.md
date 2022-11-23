# Turnout

Let's suppose for some reason your ISP is incapable to grant you reliable access to some specific websites. In such case, many of us ended up with a dual-connection plan.

A main connection provided by the ISP as is, is complemented by a second connection circumventing the problem of the first. The second route is usually metered, and accessible via a proxy (HTTP/HTTPS/SOCKS5) interface.

Turnout is aimed to give users smooth browsing experience while minimizing the traffic ($$) incurred on the metered connection, by doing smart routing in the background.

```
User ------ Router ---(ISP)---- Route 1 (default unreliable route)
               |
               -----(Proxy)---- Route 2 (metered reliable route)
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
  
### Smart routing

- COW

  Only use secondary routes if the site is blocked on the main route.
  
  ✔ Save traffic to minimum
  
  ✔ No need to keep any list
  
  ❌ Need learning at startup
  
  ❌ No transparent proxy (not supposed to be used on routers)
  
- Turnout

  Smart routing like COW but more efficient and works great on routers.
  
  ✔ Save traffic to minimum
  
  ✔ No list is needed
  
  ✔ No learning curve
  
  ✔ Work as both an HTTP proxy (all platforms) and a transparent proxy (Linux only)
  
  ✔ Slow download detection
  
  ✔ Sniff hostnames for better speed via proxy
  
  ✔ Live with bogus DNS results
  
  ✔ Support multiple proxies as upstream with customizable fail-over solution
  
  ❌ No UDP, no DNS and tunneling tools integrated (routing only)
  
### Technical highlights

- Smart selection of routes

  For TLS connections, Turnout attempts connections via the main route and all priority-1 proxies simultaneously. If none of them works then priority-2 proxies are tried. The fastest server that sends back a valid first byte will be chosen. 
  
  For other protocols, attempts are made one at a time according to priority settings (main route, priority-1, priority-2...), because sending the same content via multiple routes may lead to errors.
  
- Destination-based server switch

  By default, Turnout saves the route choice for a new destination (by full hostname, or IP if hostname is not available) and makes sure that following connections use the same server. The route choice is reset if two consecutive attempts has failed or there has been no connection to the given destination for at least 30 seconds.
  
  This feature can help alleviating the problem of IP switching with some websites. Use `-fastswitch` option if you want to disable it.
  
- Fail-over design

  Turnout does not monitor the status of the proxies like Clash. All servers are attempted according to the mechanism described above and the failure of one or two servers should not lead to downtime of the service. However, it's inefficient to entirely rely on this fail-over design by specifying a large number of servers, especially of the same priority, which can be CPU-intensive.
  
  You are recommended to put in place your own monitoring in parallel to Turnout. For example, you can specify 3 servers for Turnout and periodically monitor them based on some rules. If any one of them is deemed down, replace it with another one serving the same port so that Turnout does not need to restart.

### Basic usage

  Note: Turnout is supposed to be deployed on local network. It is not safe or optimized to use it in a remote environment, such as a VPS.
  
- Transparent proxy (Linux only)

  Both TPROXY (use `-t` option) and REDIRECT modes are supported. You need to redirect the traffic to Turnout using iptables. 
  
  REDIRECT mode is an old feature available on nearly all devices and also easy to configure. It supports IPv6 since kernel 3.7.
  TPROXY mode is a bit faster than REDIRECT but TPROXY kernel module may be missing on some old systems. On standard kernels, TPROXY is available since 2.6.28 and supports IPv6 since 2.6.37.
  
  This example starts a transparent proxy at port 2222 and sets 127.0.0.1:1080 as the upstream SOCKS5 proxy. Connections with download speed less than 100 kB/s will be added to slow list and routed via route 2 from the next connection. Incoming LAN traffic from interface br0 to non-local addresses is redirected to the proxy.
  
  ```shell
  # Start Turnout in the background
  turnout -b 0.0.0.0:2222 -s 127.0.0.1:1080 -t -slow 100 &
  
  # Option 1: Set up REDIRECT for all outgoing traffic (CPU-intensive)
  iptables -t nat -A PREROUTING -i br0 ! -d 192.168.0.0/16 -p tcp -j REDIRECT --to-ports 2222
  
  # Option 2: Set up REDIRECT for international traffic only (recommended if TPROXY is not available, ipset support and a domestic CIDR list are needed)
  iptables -t nat -A PREROUTING -i br0 ! -d 192.168.0.0/16 -p tcp -m set ! --match-set domestic dst -j REDIRECT --to-ports 2222
  
  # Option 3: Set up TPROXY for international traffic only (recommended, ipset support and a domestic CIDR list are needed)
  iptables -t mangle -N DIVERT
  iptables -t mangle -A DIVERT -j MARK --set-mark 1
  iptables -t mangle -A DIVERT -j ACCEPT
  ## This line matches established connections
  iptables -t mangle -A PREROUTING -m socket --transparent -j DIVERT
  ## These lines match new and related connections
  iptables -t mangle -A PREROUTING -i br0 ! -d 192.168.0.0/16 -m state --state NEW -p tcp -m set ! --match-set domestic dst -j CONNMARK --set-mark 1
  iptables -t mangle -A PREROUTING -i br0 -m connmark --mark 1 -p tcp -j TPROXY --on-port 2222 --tproxy-mark 1
  ## Rule for redirecting to local
  ip rule add fwmark 1 table 100
  ip route add local 0.0.0.0/0 dev lo table 100
  ```
  
  Multiple proxies can be configured to provide fail-over function. 3 priority grades can be set and lower grade servers are only used if higher grade servers fail. In this example, 192.168.1.1:1080 is set as main server (with priority 1) and 192.168.2.1:1080 and 192.168.2.1:1081 are priority-2 servers. Once 192.168.1.1:1080 fails, these two servers will be tried at the same time and the faster one will convey the traffic. You can set priorities according to the prices of the servers, for example.
  
  ```shell
  turnout -b 0.0.0.0:2222 -s 192.168.1.1:1080 -s2 192.168.2.1:1080,192.168.2.1:1081 -t
  ```
  
- Local HTTP proxy

  This command starts an HTTP proxy at local port 8080 and sets 127.0.0.1:1080 as the upstream SOCKS5 proxy. Connections with download speed less than 100 kB/s will be added to slow list and routed via route 2 from the next connection.
  
  Local HTTP proxy and transparent proxy can be enabled at the same time.
  
  ```shell
  turnout -h 127.0.0.1:8080 -s 127.0.0.1:1080 -slow 100
  ```

- IP and host lists

  Turnout is supposed to be doing routing automatically without the help of any list. But it still supports these lists for the use by advanced users. Please refer to the sample lists to learn about the format.

- Proxy schemes

  Turnout was originally designed to work only with SOCKS5 proxies. Support for HTTP/HTTPS proxies has recently been added.

  You can specify the address and scheme in URL form. Authentication is also supported.

  Please note that for HTTPS proxies, standard TLS requirements apply (such as hostname check, trust CA).

  Examples:

  ```
  127.0.0.1:1080 or socks5://127.0.0.1:1080   # SOCKS5 proxy
  http://192.168.1.1:8080                     # HTTP proxy
  http://username:password@192.168.1.1:8080   # HTTP proxy with authentication
  https://a-fake-proxy.com:443                # HTTPS proxy
  ```

- System signal

  Turnout has borrowed the idea from dnsmasq to perform actions upon receiving certain kill signals.
  
  - SIGHUP
  
    IP and host rules are re-read from the files. 
    
    This is useful when you modified the rules but do not want to rerun. Ongoing connections will not be affected.
    
  - SIGUSR2 (not available on Windows)
  
    Close and reopen the log file. 
    
    Used after you have rotated the log file, either by hand (`mv`) or with logrotate.

### Known issues

  - Linux open files limit
  
    The default open files limit on Linux is 1024. You can check it by running `ulimit -n`.
    
    By the proxy nature Turnout uses a large number of connections and is hence very likely to reach the limit. You are strongly advised to increase that number. 
    For example this command sets limit to 10000 and starts Turnout if successful.
    
    ```shell
    ulimit -n 10000 && turnout -b 0.0.0.0:2222 -s 127.0.0.1:1080 -t
    ```
    
  - Unexpected closure of TLS connections
  
    In some circumstances, the server (or some intermediary) may cut the connection before it should close. 
    Due to TLS connections' encrypted nature, Turnout may not be able to tell if the closure is normal and thus cannot identify the blockage.
    
  - DNS
  
    Turnout is written with the assumption that DNS results can be bogus. Generally speaking, if a bogus result leads to nowhere, Turnout can detect it and use route 2 automatically. However, there are some circumstances that Turnout might need your help, such as in a plain text HTTP hijack. In case that Turnout is unable to tell there's a hijack, you might need to add a rule for that IP. 
    
    If you have set up a reliable nameserver as system resolver, you are very welcome to use it but you also need to make sure it is optimized for CDNs in the main route. Please use `-dnsok` option to assert the results are genuine so that Turnout can skip some unnecessary checks.
    
  - Hostname sniffing
  
    In transparent proxy mode, for any traffic sent over route 2, Turnout tries to sniff hostnames from the first packet and send them instead of IPs to proxies to allow name resolution on the remote side, so that the speed is not affected by the local DNS result.
    
    HTTP and TLS connections are supported but TLS with ESNI is not because the hostname is encrypted. Cloudflare supports ESNI since 2018 but among major browsers only Firefox supports it (disabled by default). You are recommended to not use ESNI with Turnout.
    
  - Unreliable ISP
  
    Turnout is not supposed to be using with highly unreliable ISPs. If your ISP can't provide at least acceptable quality in international or cross-ISP connections (for instance packets are heavily throttled or randomly dropped), your better choice is an IP/CIDR based routing plan. Because in that case any benefit from automatic routing will be erased by the poor network condition.
    
### Credits

  Turnout is similar in idea to but not based on the code of COW. Therefore please do not expect the same behavior.
  
  Turnout has used these external packages, either directly or by modifying their code:
  
  - golang.org/x/crypto by Google
  
  - golang.org/x/net by Google

  - github.com/mwitkow/go-http-dialer by Michal Witkowski
  
  - Avege by missdear (only to obtain original destinations)
