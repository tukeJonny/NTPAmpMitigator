#-*- coding: utf-8 -*-

#from ryu.app import simple_switch_13
#import mitigate_switch_13#my custom simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import (
    MAIN_DISPATCHER,
    DEAD_DISPATCHER
)
from ryu.controller.handler import set_ev_cls

MITIGATE_MODE_ON = True
if MITIGATE_MODE_ON:
    import mitigate_switch_13
    super_class = mitigate_switch_13.MitigateSwitch13
else:
    from ryu.app import simple_switch_13
    super_class = simple_switch_13.SimpleSwitch13

class NTPAmpMitigator(super_class):

    def __init__(self, *args, **kwargs):
        super(NTPAmpMitigator, self).__init__(*args, **kwargs)
        self.datapaths = {}

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
