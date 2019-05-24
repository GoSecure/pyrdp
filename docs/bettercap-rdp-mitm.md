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

## Setup

Install PyRDP by following these steps : https://github.com/GoSecure/pyrdp#installing

Install Bettercap by running these commands :

    sudo apt-get update
    sudo apt-get install build-essential libpcap-dev libusb-1.0-0-dev libnetfilter-queue-dev
    mkdir -p $GOPATH/src/github.com/GoSecure/
    cd $GOPATH/src/github.com/GoSecure/
    git clone https://github.com/GoSecure/bettercap.git -b rdp-mitm
    cd bettercap
    go get
    go build

Install Caplets by running these commands :

    cd
    git clone https://github.com/GoSecure/caplets.git
    cd caplets
    sudo make install

## Usage

Start bettercap with :

    sudo bettercap -iface <interface> -caplet <caplet>

Basic example :

    sudo bettercap -iface wlp2s0 -caplet rdp-proxy/rdp-sniffer.cap

We currently have 2 caplets. Read each caplet for further documentation and usage. Here's a quick rundown :

<dl>
  <dt>rdp-proxy/rdp-sniffer.cap</dt>
  <dd>The default caplet. Forwards every target to a PyRDP instance if they have disabled NLA.</dd>

  <dt>rdp-proxy/rdp-sniffer-nla-redirect.cap</dt>
  <dd>Will forward every target to a PyRDP instance if they have disabled NLA. Otherwise, redirect the client to a user-defined non-NLA host.</dd>
  <dd>Requires some configuration inside the caplet at ~/caplets/rdp-proxy/rdp-sniffer-nla-redirect.cap</dd>
  <dd>Don't forget to `sudo make install` after editing the caplet.</dd>
</dl>

Have fun!
