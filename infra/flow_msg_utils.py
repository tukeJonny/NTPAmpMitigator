#-*- coding: utf-8 -*-
import time

class Debug(object):

    def __init__(self):
        pass

    def request_stat(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        time.sleep(5)