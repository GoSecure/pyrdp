# Transparent Proxying Examples

This document provides example network configurations for transparent
proxying (TPROXY). Its purpose is to provide a starting point for
people with specific transparent proxy needs. Network configuration
can and will vary significantly depending on the environment in which
PyRDP is deployed. It is likely that the examples below will not work
as-is and require modifications and testing during deployment.


There are two base modes for transparent proxying:

1. A single server is targeted and poisoned to reply to the MITM. The
   MITM thus impersonates a single server and both clients and server
   will not be aware of the proxy. This mode is useful for honeypots.
   
2. No server is targeted and the MITM will establish a direct
   connection to the intended server. In this mode, the server will
   see connections as coming from the MITM, but clients will not be
   aware of the proxy. This mode is useful when ARP poisoning a subnet
   during engagements.


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

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Route RDP traffic intended for the target server to local PyRDP (1)
iptables -t mangle -I PREROUTING -p tcp -d $SERVER_IP --dport 3389 \
  -j TPROXY --tproxy-mark $MARK --on-port 3389 --on-ip 127.0.0.1

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

Then launch PyRDP. In this case it should be launched like this:

```
pyrdp-mitm --transparent 10.2.2.2
```


## L2 Bridge to L3 TPROXY Interception

This is a more advanced setup where the MITM is a bridge between two
interfaces. It allows L2 protocols (broadcasts, ARP, DHCP, etc.) through making
it almost invisible to the hosts in the network and allowing inline
deployments. Only traffic destined for the target server on port 3389 is ever
processed at the IP level and redirected to the MITM through `ebtables` rules.

We are also including an out-of-band management interface with it's own routing
table (for Internet access) as part of the documentation of that setup. The
bridge is isolated using Linux network namespaces and only PyRDP has access to
it. All the host traffic will go through the management interface otherwise.
The network namespace isolation is important if intercepted clients need to be
routed back to their origin. Both the MITM and the host will have to have
access to potentially conflicting routes, especially if intercepting clients
from the Internet, and each using their own interfaces. Linux network
namespaces achieve that isolation best.

```
                         enp0s9 (mgmt)
                           |
                        +------+
                        | HOST |
   +--------+           |------|             +--------+
   | CLIENT | <-- 1 --> | MITM | <--- 2 ---> | SERVER |
   +--------+           +------+             +--------+
   10.13.37.10       /     br0    \         10.13.37.111
                enp0s3            enp0s8
```

### Setup

Configure your host interface first. Then let's assign a few variables to make
the setup easy to re-use in other contexts.

**config.sh**:
```bash
# The IP of the RDP server which want to intercept
export SERVER_IP=10.13.37.111

# Required to be able to route packets
export GATEWAY_IP=10.13.37.10
export LOCAL_NET=10.13.37.0/24

# Required by ARP pinning (option 2)
export GATEWAY_MAC=08:00:27:59:05:fe
export SERVER_MAC=08:00:27:2d:b6:50

# Interface that faces the server
export SERVER_IF=enp0s8

# Interface that faces clients
export CLIENT_IF=enp0s3

# Name of the network namespace (should be fine as-is)
export MITM_NS=mitm

# The mark number to use in iptables (should be fine as-is)
export MARK=1

# The routing table ID for custom rules (should be fine as-is)
export TABLE_ID=100
```

Remember to `source config.sh` and not execute (ie: `./config.sh`) otherwise
the exports disappear when the subshell terminates.

Run the following script to setup the host interfaces and get in the namespace.

**pre-setup.sh**:
```bash
#!/bin/bash -x
#
# Creates the 'mitm' network namespace
ip netns add $MITM_NS

# Assign the input and output interfaces to the created namespace.
# They will disappear from the host and stop working so be careful not to lock
# yourself out of the server.
ip link set dev $CLIENT_IF netns $MITM_NS
ip link set dev $SERVER_IF netns $MITM_NS

# Spawn a bash shell inside the network namespace
ip netns exec $MITM_NS /bin/bash
```

Run the following script to configure namespace interfaces, bridge and prepare
routing tables.

**setup.sh**:
```bash
#!/bin/bash -x
#
# Enable the loopback interface in the namespace
ip link set dev lo up

# Setup the bridge for L2 interception of traffic between the two interfaces
ip link add name br0 type bridge
ip link set $CLIENT_IF master br0
ip link set $SERVER_IF master br0
# Set forward delay to 0
brctl setfd br0 0
ip link set $CLIENT_IF up
ip link set $SERVER_IF up
ip link set br0 up

# Create a custom routing table for pyrdp traffic
echo "$TABLE_ID    pyrdp" >> /etc/iproute2/rt_tables

# Set route lookup to the pyrdp table for marked packets.
ip rule add fwmark $MARK lookup $TABLE_ID

# Add a custom route that redirects traffic intended for the outside world to loopback
# So that server-client traffic passes through PyRDP (2)
# This table will only ever be used by RDP so it should not be problematic
ip route add local default dev lo table $TABLE_ID

# This setting ensures that bridged traffic is sent to iptables for processing
# WARNING: if you have other important firewall rules, make sure to test the impact of this
modprobe br_netfilter
echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables

# Disable return path filtering
echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/$CLIENT_IF/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/$SERVER_IF/rp_filter
```

In order for L3 traffic to be properly routed between the client and servers, there are two options.

#### Option 1: Routing with a default route and ARP resolutions

This option works when you can allow ARP resolutions on the subnet of the
server you want to intercept. Adding a default gateway will allow the MITM to
reach all IP addresses that are not link-local.

Remember to do this in the previously configured network namepsace.

```
ip route add $LOCAL_NET dev br0
ip route add default via $GATEWAY_IP dev br0
```

We recommend you add this to the end of the `setup.sh` script.

ARP resolutions will look like this:

```
19:06:47.790619 ARP, Request who-has 10.13.37.10 tell 0.0.0.0, length 28
19:06:47.791701 ARP, Reply 10.13.37.10 is-at 08:00:27:59:05:fe (oui Unknown), length 46
19:06:49.439537 ARP, Request who-has 10.13.37.111 tell 0.0.0.0, length 28
19:06:49.439804 ARP, Reply 10.13.37.111 is-at 08:00:27:2d:b6:50 (oui Unknown), length 46
```


#### Option 2: Routing with a default route and ARP pinning

To be stealthier, not issuing ARP requests on the subnet is even better, but
this requires pinning ARP entries so that the MITM is able to resolve the IP of
the gateway and the server. The system will still be configured with L3
information but it will be satisfied by the underlying pinned ARP entries so no
ARP requests will leak on the network.

The good thing about this approach is that the MITM will be harder to detect
because it will not broadcast ARP at all. The problem with it is that it
requires prior knowledge of the intended server and of the gateway's MAC and IP
addresses, and that any dynamic change to those will invalidate the
configuration and cause a connectivity outage.

Two ARP entries need to be added:

- The server itself
- The server's gateway

The command to use to pin an ARP entry is `arp -i br0 -s <ip_addr> <mac_addr>`

Remember to do this in the previously configured network namepsace.

```bash
ip route add $LOCAL_NET dev br0
ip route add default via $GATEWAY_IP dev br0
arp -i br0 -s $GATEWAY_IP $GATEWAY_MAC
arp -i br0 -s $SERVER_IP $SERVER_MAC
```

We recommend you add this to the end of the `setup.sh` script.

Optionally, it might be a good idea to disable outbound ARP requests to prevent
the host from accidentally sending ARP requests to the bridge:

```bash
arptables -A OUTPUT -o br0 -j DROP
```


### Start

Inside the network namespace, run the following script to activate the interception.
**activate.sh**:
```
#!/bin/bash -x
#
# Intercept RDP traffic destined for the server (1)
# Layer 2
# The ebtables broute DROP target passes packets up to iptables for processing
# Note that on some Linux distributions ebtables-legacy should be used instead of ebtables
ebtables -t broute -A BROUTING -i $CLIENT_IF -p ipv4 --ip-dst $SERVER_IP \
  --ip-proto tcp --ip-dport 3389 -j redirect --redirect-target DROP
# Layer 3
# Redirect matching traffic to localhost leveraging Linux's TPROXY feature
iptables -t mangle -I PREROUTING -p tcp -d $SERVER_IP --dport 3389 \
  -j TPROXY --tproxy-mark $MARK --on-port 3389 --on-ip 127.0.0.1

# Mark RDP return traffic intended for clients (2)
# Layer 2
ebtables -t broute -A BROUTING -i $SERVER_IF -p ipv4 --ip-src $SERVER_IP \
  --ip-proto tcp --ip-source-port 3389 -j redirect --redirect-target DROP
# Layer 3
iptables -t mangle -A PREROUTING -s $SERVER_IP -m tcp -p tcp --sport 3389 \
    -j MARK --set-mark $MARK
```

Then launch PyRDP. In this case it should be launched like this:

```
pyrdp-mitm --transparent $SERVER_IP
```

### Stop

The following script will deactivate interception.
**deactivate.sh**:
```
ebtables -t broute -F BROUTING
iptables -t mangle -F PREROUTING
```

## More

Other scenarios might require creativity with route configuration and are left to the reader's imagination.


# Useful References

* The [GitHub issue][204] where this documentation was developed
* TPROXY documentation: https://powerdns.org/tproxydoc/tproxy.md.html
* Kernel docs: https://www.kernel.org/doc/Documentation/networking/tproxy.txt
* Netfilter Packet Flow: https://upload.wikimedia.org/wikipedia/commons/3/37/Netfilter-packet-flow.svg
* `ebtables` and `iptables` interaction caveats: https://ebtables.netfilter.org/br_fw_ia/br_fw_ia.html
* `ebtables` reference: https://ebtables.netfilter.org/
* https://github.com/rkok/bridge-mitm-tools
* https://wiki.squid-cache.org/Features/Tproxy4#Timeouts_with_Squid_running_as_a_bridge_or_multiple-NIC
* Network namespaces: https://lwn.net/Articles/580893/, https://blogs.igalia.com/dpino/2016/04/10/network-namespaces/
* Give an interface to a namespace: https://medium.com/@badbot/a-thing-with-multi-homed-linux-host-two-nics-in-one-box-f62db1de8f17
* Using bridges in network namespaces: https://ops.tips/blog/using-network-namespaces-and-bridge-to-isolate-servers/
* Manual bridge setup: https://www.tldp.org/HOWTO/BRIDGE-STP-HOWTO/set-up-the-bridge.html

[204]: https://github.com/GoSecure/pyrdp/issues/204#issuecomment-610758979
