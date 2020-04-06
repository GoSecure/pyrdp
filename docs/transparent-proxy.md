# Transparent Proxying Examples

This document provides example network configurations for transparent
proxying (TPROXY) Its purpose is to provide a starting point for
people with specific transparent proxy needs. Network configuration
can and will vary significantly depending on the environment in which
PyRDP is deployed. It is likely that the examples below will not work
as-is and require modifications and testing during deployment.


## Basic L3 TPROXY

This example is a simple Layer 3 proxy which intercepts RDP
connections.  It is applicable to environments where the MITM is
routing traffic at the IP level.

```bash
# Additional configuration required on the MITM (example)
#  +--------+           +------+             +--------+
#  | CLIENT | <-- 1 --> | MITM | <--- 2 ---> | SERVER |
#  +--------+           +------+             +--------+
#   10.6.6.6            10.1.1.1              10.2.2.2

# The IP of the RDP server which will receive proxied connections.
SERVER_IP=10.2.2.2

# The mark number to use in iptables (should be fine as-is)
MARK=1

# The routing table ID for custom rules (should be fine as-is)
TABLE_ID=100

# Create a custom routing table for pyrdp traffic
echo "$TABLE_ID    pyrdp" >> /etc/iproute2/rt_tables

# Route RDP traffic intended for the target server to local PyRDP (1)
iptables -t nat \
    -A PREROUTING \
    -d $SERVER_IP \
    -p tcp -m tcp --dport 3389 \
    -j REDIRECT --to-port 3389

# Mark RDP traffic intended for clients (2)
iptables -t mangle -A PREROUTING \
    -s $SERVER_IP \
    -m tcp -p tcp --sport 3389 \
    -j MARK --set-mark $MARK

# Set route lookup to the pyrdp table for marked packets.
ip rule add fwmark $MARK lookup $TABLE_ID

# Add a custom route that redirects traffic intended for the outside world to loopback
# So that server-client traffic passes through PyRDP
# This table will only ever be used by RDP so it should not be problematic
ip route add local default dev lo table $TABLE_ID
```


## L2 Bridge to L3 TPROXY Interception

This is a more advanced setup where the MITM is a bridge between two interfaces. It allows L2 protocols (Broadcast, ARP,
DHCP) through and does not have an IP address in the source/target networks, making it almost invisible to the hosts in
the network. Only traffic destined for the target server on port 3389 is ever processed at the IP level and redirected
to the MITM through `ebtables`.


**Netplan**
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: no
    enp0s8:
      dhcp4: no
    # management interface
    enp0s9:
      dhcp4: yes
  bridges:
    br0:
      interfaces:
        - enp0s3
        - enp0s8
      # if you are confident that your deployment is not going
      # to cause a loop you should leave these enabled, otherwise comment them
      parameters:
        stp: false
        forward-delay: 0
```

**setup.sh**

```shell
#!/bin/bash -x
#               enp0s3            enp0s8
#  +--------+         \ +------+ /           +--------+
#  | CLIENT | <-- 1 --> | MITM | <--- 2 ---> | SERVER |
#  +--------+           +------+             +--------+
#  10.13.37.10             br0              10.13.37.111

# The IP of the RDP server which will receive proxied connections.
SERVER_IP=10.13.37.111

# The mark number to use in iptables (should be fine as-is)
MARK=1

# The routing table ID for custom rules (should be fine as-is)
TABLE_ID=100

# Create a custom routing table for pyrdp traffic
echo "$TABLE_ID    pyrdp" >> /etc/iproute2/rt_tables

# Intercept RDP traffic destined for the server (1)
iptables -t mangle -I PREROUTING -p tcp -d 10.13.37.111 --dport 3389 \
  -j TPROXY --tproxy-mark 0x1/0x1 --on-port 3389 --on-ip 127.0.0.1

# Mark RDP return traffic intended for clients (2)
iptables -t mangle -A PREROUTING \
    -s $SERVER_IP \
    -m tcp -p tcp --sport 3389 \
    -j MARK --set-mark $MARK

# Set route lookup to the pyrdp table for marked packets.
ip rule add fwmark $MARK lookup $TABLE_ID

# Add a custom route that redirects traffic intended for the outside world to loopback
# So that server-client traffic passes through PyRDP
# This table will only ever be used by RDP so it should not be problematic
ip route add local default dev lo table $TABLE_ID

# If you want the interception to happen at the Layer 2
# Make sure that both your interfaces are bridged together

# WARNING: if you have other important firewall rules, make sure to test the impact of this
modprobe br_netfilter
echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables

# Target DROP in brouting means out of L2 go route in L3
ebtables -t broute -A BROUTING -i enp0s3 -p ipv4 --ip-dst $SERVER_IP --ip-proto tcp --ip-dport 3389 -j redirect --redirect-target DROP
ebtables -t broute -A BROUTING -i enp0s8 -p ipv4 --ip-src $SERVER_IP --ip-proto tcp --ip-source-port 3389 -j redirect --redirect-target DROP
# recent linux like debian buster
#ebtables-legacy -t broute -A BROUTING -i enp0s8 -p ipv4 --ip-src $SERVER_IP --ip-proto tcp --ip-source-port 3389 -j redirect --redirect-target DROP

# Disable return path filtering
echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/enp0s3/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/enp0s8/rp_filter

# Make interception work without an IP assigned to br0
# WARNING: unclear if required on not
echo 1 > /proc/sys/net/ipv4/conf/br0/route_localnet
echo 1 > /proc/sys/net/ipv4/conf/enp0s3/route_localnet

# Mark socket Packets
# WARNING: Unclear if required or not but likely good for performance so it will likely stay
iptables -t mangle -N DIVERT
iptables -t mangle -A DIVERT -j MARK --set-mark 1
iptables -t mangle -A DIVERT -j ACCEPT
iptables -t mangle -I PREROUTING -p tcp -m socket -j DIVERT
```

In order for L3 traffic to be properly routed between the client and servers, there are two options.

### Option 1: Add an Interface with a valid IP in the networks of interests on the Bridge

This is important to allow ARP resolution to work properly (when the MITM unavoidably needs to know who has the
server/client IP)

In the example setup, doing something like below is enough to make everything work because when the MITM needs the L2
address to reply to, it has the means to look it up by itself.

```
ip addr add 10.13.37.11/24 dev br0
```

### Option 2: ARP Pinning

To be stealthier, not having any routable L3 address is even better, but this requires to pin ARP cache entries so that
the MITM is able to resolve any `WHO HAS x, TELL mitm` queries. The good thing about this approach is that the MITM will
be harder to detect because it will not broadcast ARP at all. The problem with it is that it requires prior knowledge of
the intended server and of the gateway's MAC and IP addresses, and that any dynamic change to those will invalidate the
configuration and cause a connectivity outage.

Two ARP entries need to be added:

- The server itself
- The server's gateway

The command to use to pin an ARP entry is `arp -i br0 -s <ip_addr> <mac_addr>`

In the example above, the two commands might be issued if the gateway for the server is configured as `10.13.37.1`:

```bash
arp -i br0 -s 10.13.37.1 08:00:27:59:05:f0
arp -i br0 -s 10.13.37.111 08:00:27:59:05:fe
```

# Useful References

* TPROXY documentation: https://powerdns.org/tproxydoc/tproxy.md.html
* Kernel docs: https://www.kernel.org/doc/Documentation/networking/tproxy.txt
* Netfilter Packet Flow: https://upload.wikimedia.org/wikipedia/commons/3/37/Netfilter-packet-flow.svg
* `ebtables` and `iptables` interaction caveats: https://ebtables.netfilter.org/br_fw_ia/br_fw_ia.html
* `ebtables` reference: https://ebtables.netfilter.org/
* https://github.com/rkok/bridge-mitm-tools
* https://wiki.squid-cache.org/Features/Tproxy4#Timeouts_with_Squid_running_as_a_bridge_or_multiple-NIC
