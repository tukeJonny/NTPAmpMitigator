#!/usr/bin/env bash

#mininet@mininet-vm:~/NTPAmpMitigator/infra/kickstart$ sudo ./create_network.sh
#*** Creating network
#*** Adding controller
#Unable to contact the remote controller at 127.0.0.1:6633
#*** Adding hosts:
#h1s1 h2s1 h3s1 h4s1
#*** Adding switches:
#s1
#*** Adding links:
#(h1s1, s1) (h2s1, s1) (h3s1, s1) (h4s1, s1)
#*** Configuring hosts
#h1s1 h2s1 h3s1 h4s1
#*** Running terms on localhost:10.0
#*** Starting controller
#c0
#*** Starting 1 switches
#s1
#*** Starting CLI:
#mininet> pingall
#*** Ping: testing ping reachability
#h1s1 -> h2s1 h3s1 h4s1 nat0
#h2s1 -> h1s1 h3s1 h4s1 nat0
#h3s1 -> h1s1 h2s1 h4s1 nat0
#h4s1 -> h1s1 h2s1 h3s1 nat0
#nat0 -> h1s1 h2s1 h3s1 h4s1
#*** Results: 0% dropped (20/20 received)

# --topo linear,1,4
#        s1
#        |
#   -----------
#   |  |   |   |
#   h1 h2  h3  h4


mn --nat \
   --topo linear,1,4 \
   --mac \
   --switch ovsk \
   --controller remote \
   -x \
   --link=tc,bw=1000 #Please save your pc.