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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4 as ipv4
from ryu.lib.packet import ether_types

from flow_msg_utils import is_ipv4_belongs_to_network
from flow_msg_utils import FlowModHelper

class MitigateSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet
    }

    def __init__(self, *args, **kwargs):
        super(MitigateSwitch13, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']

        self.subnet = ("10.0.0.0","255.0.0.0")
        # self.detect_match_rule = {
        #     'eth_type': ether.ETH_TYPE_IP,
        #     'ipv4_src': self.subnet,
        #     #'in_port': None,
        #     #'eth_dst': None,
        # }
        self.mac_to_port = {}

        self.flow_mod_helper = FlowModHelper()

        self.NAT_IN_PORT = 4 # h1 h2 h3 h4 nat
                                #           |_this
        self.SLEEP_TIME = 60
        #self.ADDITIONAL_SLEEP_TIME = 5 #生成したスレッドが、hard_timeoutとタイミングを合わせられるように調節
        self.MITIGATE_MODE = False

    ##### Switch feature handler #####
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        self.flow_mod_helper.init_flow_table(datapath)

    ##### Utils #####
    def get_datapathes(self):
        datapathes = [dp for _, dp in self.dpset.get_all()]
        return datapathes

    ##### Mitigate Entry & Exit #####
    def mitigate_entry(self, datapath):
        self.MITIGATE_MODE = True
        self.logger.info("[*] Mitigate Entry (MITIGATE_MODE={})".format(self.MITIGATE_MODE))

        self.flow_mod_helper.change_flow_mitigate_entry(datapath)

        # Spawn mitigate_exit
        self.logger.info("[+] Spawn mitigate_exit process")
        hub.spawn(self.mitigate_exit, datapath)

    def mitigate_exit(self, datapath):
        #hard_timeoutとギリギリのタイミングになるので、+5ぐらいしておく
        #hard_timeoutどこにも指定していなかったので、修正。動くか確認
        time.sleep(self.SLEEP_TIME)#+self.ADDITIONAL_SLEEP_TIME)

        self.flow_mod_helper.change_flow_mitigate_exit(datapath)

        self.logger.info("[-] Mitigate Exit (MITIGATE_MODE = {})".format(self.MITIGATE_MODE))
        self.MITIGATE_MODE = False

    ##### Packet-In Handler #####

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

        # Filtering( ignore lldp packet )
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        #Learning
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # Out port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # ARP (ARP Floodをフローエントリに追加したらダメ)
        if out_port != ofproto.OFPP_FLOOD:
            self.flow_mod_helper.add_normal_arp(datapath, in_port, dst, actions)

        # Filtering 2
        #NAT側から通ってきたパケットはフィルタリングしない
        #IPv4アドレスが偽装されていると検知した場合、MITIGATE ENTRYする
        if pkt_ipv4 is not None and in_port != self.NAT_IN_PORT:
            ipv4_src = pkt_ipv4.src.decode("utf-8")
            if not is_ipv4_belongs_to_network(ipv4_src, self.subnet):
                self.logger.info("[!!] filter packet from {}".format(ipv4_src))
                if not self.MITIGATE_MODE:
                    # FlowMod Remove table-miss Packet-In Entry
                    self.logger.info("[*] MITIGATE MODE ON")
                    self.mitigate_entry(datapath)
                return

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            is_nat = in_port == self.NAT_IN_PORT
            self.flow_mod_helper.add_normal_packet_in(datapath, in_port, out_port,
                                                      dst, buffer_id=msg.buffer_id, nat=is_nat)
        else:
            self.logger.info("[*] This packet's out_port is FLOODING")

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        else:
            self.logger.info("[!] There is no buffer, But data isn't specified!")
            self.logger.info("    Ignore this packet.")
            return

        self.flow_mod_helper.normal_packet_out(datapath, msg.buffer_id, in_port,
                                               actions, data)
