#-*- coding: utf-8 -*-

#既存のフロールールを全て一旦削除
#それらのフロールールで指定していたMatchにIPアドレス情報(サブネット)を追加
#mitigate時はなんでもPacket-Inするルールは不要なので削除したまま
#mitigate後はなんでもPacket-Inするルールから突っ込んでいく
import logging
import socket
import struct
import ipaddress

class FlowRule(object):
    def __init__(self, datapath, priority, match, actions, ):
        pass

class FlowRuleManager(object):
    def __init__(self):
        self.matches = {
            'match': []
        }

    def register_match(self, config):
        self.matches['match'].append(config)





#packet_in_handlerにて、受け取ったパケットのipv4がsubnetに属するか調べるのに必要
def is_ipv4_belongs_to_network(ipv4, network):
    # netmask -> CIDR
    network, netmask = network
    network_address = socket.inet_pton(socket.AF_INET, netmask)
    cidr_value = bin(struct.unpack('!L', network_address)[0])[2:].index('0')
    cidr = "{network}/{cidr_value}".format(**locals())

    #check
    ipv4 = ipaddress.ip_address(ipv4)
    ipv4_network = ipaddress.ip_network(cidr.decode("utf-8"))

    return ipv4 in ipv4_network



