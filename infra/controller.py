#-*- coding: utf-8 -*-

import pprint
from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.lib import hub
from ryu.controller import ofp_event
from ryu.controller.handler import (
    MAIN_DISPATCHER,
    DEAD_DISPATCHER
)
from ryu.controller.handler import set_ev_cls

class NTPAmpMitigator(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(NTPAmpMitigator, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mitigate_match_rule = {
            'ipv4_src': "10.0.0.0",
            'nw_src_mask': 8
        }

        self.monitor_thread = hub.spawn(self._monitor)

        self.flag = True

        self.MITIGATE_RULE_EXISTS = False

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                if self.flag:
                    self.logger.info("[+] Add Mitigate Rule!")
                    self._add_mitigate_rule(dp)
                    self.flag = False
                else:
                    self.logger.info("[+] Del Mitigate Rule!")
                    self._del_mitigate_rule(dp)
                    self.flag = True
            hub.sleep(10)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        for stat in sorted([flow for flow in body if flow.priority == 1], key=lambda flow: (flow.match['in_port'],flow.match['eth_dst'])):
            self.logger.info("[+] Flow Stats below")
            self.logger.info(stat.__dict__)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info("[+] Port Stats below")
            self.logger.info(stat.__dict__)

    def _add_mitigate_rule(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(**self.mitigate_match_rule)
        actions = []
        self.add_flow(datapath, 1, match, actions)

    def _del_mitigate_rule(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(**self.mitigate_match_rule)
        msg = parser.OFPFlowMod(
            datapath=datapath,
            match=match,
            cookie=0,
            command=ofproto.OFPFC_DELETE
        )
        datapath.send_msg(msg)



