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

This is a more advanced setup where the MITM is a bridge between two
interfaces. It specifically allows L2 protocols (Broadcast, ARP, DHCP) through and does not
have any IP address in the source/target networks.

TODO :)
