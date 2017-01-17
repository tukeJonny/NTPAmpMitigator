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
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

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

    # ARP
    def add_arp(self, datapath, in_port, eth_dest, actions):
        parser = datapath.ofproto_parser
        match_config = {
            'eth_type': ether.ETH_TYPE_ARP,
            'in_port': in_port,
            'eth_dst': eth_dest,
        }
        match = parser.OFPMatch(**match_config)

    # Mitigate Entry & Mitigate Exit
    ## Aggregate
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
        pass

    def del_drop(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = []
        self.del_flow(datapath, match, actions)

    ## Packet-In with ipv4_src check
    def add_check_packet_in(self, datapath):
        pass

    def del_check_packet_in(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(**self.detect_match_rule)
        actions = [parser.OFPActionoutput(ofproto.OFPP_CONTROLLER,
                                       ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 1, match, actions)

        # Packet-In

    # Usual Packet-In
    def add_

