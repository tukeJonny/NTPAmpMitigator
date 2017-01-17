#-*- coding: utf-8 -*-
import time

from ryu.ofproto import ether

class FlowModHelper(object):

    def __init__(self):
        self.subnet = ("10.0.0.0", "255.0.0.0")
        self.detect_match_rule = {
            'eth_type': ether.ETH_TYPE_IP,
            'ipv4_src': self.subnet,
        }

    # Common
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            msg = parser.OFPFlowMod(datapath=datapath,priority=priority,
                                match=match, instructions=inst, buffer_id=buffer_id)
        else:
            msg = parser.OFPFlowMod(datapath=datapath,priority=priority,
                                    match=match, instructions=inst)

        datapath.send_msg(msg)

    def del_flow(self, datapath, match, actions, cookie=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        msg = parser.OFPFlowMod(
            datapath = datapath,
            match=match,
            instructions=inst,
            cookie=cookie,
            command=ofproto.OFPFC_DELETE,
            buffer_id=ofproto.OFPCML_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
        )
        datapath.send_msg(msg)

    def del_all_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath,0,0,0,
                                ofproto.OFPFC_DELETE,
                                0,0,1,
                                ofproto.OFPCML_NO_BUFFER,
                                ofproto.OFPP_ANY,
                                ofproto.OFPG_ANY)
        datapath.send_msg(mod)

    # Mitigate Entry & Mitigate Exit
    ## Aggregate Mitigate Entry & Mitigate Exit
    def change_flow_mitigate_entry(self, datapath):
        pass

    def change_flow_mitigate_exit(self, datapath):
        pass

    ## Packet-In
    def add_packet_in(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def del_packet_in(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match=parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.del_flow(datapath, match, actions)
    ## Drop
    def add_drop(self, datapath):
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = []
        self.add_flow(datapath, match, actions)

    def del_drop(self, datapath):
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = []
        self.del_flow(datapath, match, actions)

    ## Packet-In with ipv4_src check
    def add_check_packet_in(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(**self.detect_match_rule)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER),
                   ofproto.OFPCML_NO_BUFFER]
        self.add_flow(datapath, 1, match, actions)

    def del_check_packet_in(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(**self.detect_match_rule)
        actions = [parser.OFPActionoutput(ofproto.OFPP_CONTROLLER,
                                       ofproto.OFPCML_NO_BUFFER)]
        self.del_flow(datapath, match, actions)

        # Packet-In

    # Normal Packet-In (priority=2)
    ## ARP
    def add_normal_arp(self, datapath, in_port, eth_dest, actions):
        parser = datapath.ofproto_parser
        match_config = {
            'eth_type': ether.ETH_TYPE_ARP,
            'in_port': in_port,
            'eth_dst': eth_dest,
        }
        match = parser.OFPMatch(**match_config)

        self.add_flow(datapath, 2, match, actions)

    ## Packet-In
    def add_normal_packet_in(self, datapath, in_port, out_port, eth_dst, buffer_id=None, nat=False):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(out_port)]
        match_rule = {'in_port': in_port, 'eth_dst': eth_dst}

        if not nat: #NATから入ってきたパケットでないなら、検知する設定
            match_rule.update(self.detect_match_rule)
        match = parser.OFPMatch(**match_rule)

        self.add_flow(datapath, 2, match, actions, buffer_id)

    ## OutPortAction
    def normal_packet_out(self, datapath, buffer_id, in_port, actions, data):
        parser = datapath.ofproto_parser
        msg = parser.OFPPacketOut(datapath=datapath,buffer_id=buffer_id,
                                  in_port=in_port,actions=actions,data=data)
        datapath.send_msg(msg)



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
