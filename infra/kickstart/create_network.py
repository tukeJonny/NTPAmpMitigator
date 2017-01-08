#!/usr/bin/env python
#-*- coding: utf-8 -*-

from mininet.cli import CLI
from mininet.link import Link
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.term import makeTerm

if '__main__' == __name__:
    net = Mininet(controller=RemoteController)

    #Controllers
    c0 = net.addController('c0')

    #Switches
    s1 = net.addSwitch('s1')

    #Hosts
    h1 = net.addHost('h1', mac='00:00:00:00:00:21')
    h2 = net.addHost('h2', mac='00:00:00:00:00:22')
    h3 = net.addHost('h3', mac='00:00:00:00:00:23')
    h4 = net.addHost('h4', mac='00:00:00:00:00:24')

    #Links
    Link(s1, h1)
    Link(s1, h2)
    Link(s1, h3)
    Link(s1, h4)

    #Start
    net.build() #Network
    c0.start() #Controller
    s1.start([c0]) #Switches

    #Open Terminal
    net.startTerms()

    #Command Line Interface
    CLI(net)

    #Terminate
    net.stop()