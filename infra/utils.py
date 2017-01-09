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
    def __init__(self, datapath, priority, match_config, actions, buffer_id=None):
        self._datapath = datapath
        self._priority = priority
        self._buffer_id = buffer_id

        self._match_config = match_config # dict
        self._actions = actions

    @property
    def datapath(self):
        return self._datapath
    @property
    def priority(self):
        return self._priority
    @property
    def buffer_id(self):
        return self._buffer_id
    @property
    def match_config(self):
        return self._match_config
    @property
    def actions(self):
        return self._actions

class FlowRuleManager(object):
    def __init__(self):
        self.datapath = None
        self.flow_rules = []

    def register(self, flow_rule):
        self.flow_rules.append(flow_rule)

    def create_any_match_flow_rule(self):
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        return (
            self.datapath,
            0,
            match,
            actions,
        )


    def mitigate_entry_generator(self, datapath):
        """
        datapath.send(:return:)
        :param datapath:
        :return:
        """
        self.datapath = datapath
        for flow_rule in self.flow_rules:
            datapath = flow_rule.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(**flow_rule.match_config)
            msg = parser.OFPFlowMod(
                datapath=datapath,
                match=match,
                cookie=0,
                command=ofproto.OFPFC_DELETE
            )
            yield (datapath, msg)

    def mitigate_exit_generator(self):
        """
        self.add_flow(**:return:)
        :return:
        """
        if self.any_datapath is None:
            raise ValueError("Controller is not MITIGATE MODE!")

        #First, add ANY Match Flow Entry
        yield self.create_any_match_flow_rule()

        for flow_rule in self.flow_rules:
            datapath = flow_rule.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(**flow_rule.match_config)
            actions = flow_rule.actions
            buffer_id = flow_rule.buffer_id

            yield (
                datapath,
                1,
                match,
                actions,
                buffer_id
            )

        self.any_datapath = None #Reset






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



