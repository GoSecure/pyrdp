# Run PyRDP alongisde Bettercap

Here is a short tutorial on how to combine the PyRDP and Bettercap to
redirect all RDP sessions on a LAN segment. By default, Bettercap's arp 
spoofing module will spoof the entire subnet over a given interface. We 
will spawn an instance of PyRDP for each incoming RDP connections if they
are in our target list, otherwise we will forward them.

## Requirements

1. PyRDP  
2. Our fork and branch of Bettercap [https://github.com/GoSecure/bettercap/tree/rdp-mitm]
3. Our fork of Caplets [https://github.com/GoSecure/caplets/]
4. (Optional) rdp-sec-check [https://github.com/portcullislabs/rdp-sec-check]

## Usage

Start bettercap with :

    bettercap -iface <interface> -caplet <caplet>

We currently have 3 caplets. Read each caplet for further documentation and usage. Here's a quick rundown :

<dl>
  <dt>rdp-proxy/rdp-sniffer.cap</dt>
  <dd>The default caplet. Will forward every target to a PyRDP instance.</dd>

  <dt>rdp-proxy/rdp-sniffer-nla.cap</dt>
  <dd>Will forward every target to a PyRDP instance if they have disabled NLA.</dd>
  <dd>Requires rdp-sec-check.</dd>

  <dt>rdp-proxy/rdp-sniffer-nla-redirect.cap</dt>
  <dd>Will forward every target to a PyRDP instance if they have disabled NLA. Otherwise, redirect the client to a non-NLA host.</dd>
  <dd>Requires rdp-sec-check and some configuration inside the caplet.</dd>
</dl>

Have fun!
