#-*- coding: utf-8 -*-
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import time
import multiprocessing

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4 as ipv4
from ryu.lib.packet import ether_types
from ryu.ofproto import ether

from utils import is_ipv4_belongs_to_network
from utils import FlowRule, FlowRuleManager

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.subnet = ("10.0.0.0","255.0.0.0")
        self.detect_match_rule = {
            'eth_type': ether.ETH_TYPE_IP,
            'ipv4_src': self.subnet,
            #'in_port': None,
            #'eth_dst': None,
        }
        self.mac_to_port = {}
        self.flow_rule_manager = FlowRuleManager() # 全てにマッチするルール以外を管理

        self.SLEEP_TIME = 20
        self.MITIGATE_MODE = False

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, None, actions, any_match=True)

    def del_any_match_flow_rule(self, datapath):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()

        self.del_flow(datapath, match)

    def mitigate_entry(self, datapath):
        self.MITIGATE_MODE = True
        self.logger.info("[*] Mitigate Entry")
        self.del_any_match_flow_rule(datapath)

        # Spawn mitigate_exit
        self.logger.info("[+] Spawn mitigate_exit process")
        p = multiprocessing.Process(target=self.mitigate_exit)
        p.start()

    def mitigate_exit(self):
        time.sleep(self.SLEEP_TIME)

        #Refresh
        ##Delete flow rule (any match rule exclude)
        del_flow_gen = self.flow_rule_manager.del_flow_rule_generator()
        for datapath, msg in del_flow_gen:
            datapath.send_msg(msg)

        ##Add flow rule (any match rule include)
        add_flow_gen = self.flow_rule_manager.add_flow_rule_generator()
        for datapath,priority,match,actions,buffer_id in add_flow_gen:
            # This rule is not match any packet. but this entry is refresh entry.
            # リフレッシュで追加するだけなので、Managerに追加する必要はない
            self.add_flow(datapath,priority,match,None,actions,buffer_id=buffer_id, any_match=True)

        self.logger.info("[-] Mitigate Exit")
        self.MITIGATE_MODE = False

    def add_flow(self, datapath, priority, match, match_config, actions, buffer_id=None, any_match=False):
        if not any_match:
            # Register FlowRule to FlowRuleManager
            flow_rule = FlowRule(datapath, priority, match_config, actions, buffer_id)
            self.flow_rule_manager.register(flow_rule)

        # Add Flow
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def del_flow(self, datapath, match, cookie=0):
        ofproto = datapath.ofproto

        msg = parser.OFPFlowMod(
            datapath=datapath,
            match=match,
            cookie=cookie,
            command=ofproto.OFPFC_DELETE
        )
        datapath.send_msg(msg)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

        # Filtering
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        if pkt_ipv4 is not None:
            ipv4_src = pkt_ipv4.src.decode("utf-8")
            if not is_ipv4_belongs_to_network(ipv4_src, self.subnet):
                self.logger.info("[!!] filter packet from {}".format(ipv4_src))
                if not self.MITIGATE_MODE:
                    # FlowMod Remove ANY Packet-In Entry
                    self.logger.info("[*] MITIGATE MODE ON")
                    self.mitigate_entry(datapath)
                return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match_rule = self.detect_match_rule.copy()
            match_rule.update({'in_port': in_port, 'eth_dst':dst})
            # Managerに追加
            match = parser.OFPMatch(**match_rule)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.logger.info("[+] add_flow with buffer_id")
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.logger.info("[+] add_flow")
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
