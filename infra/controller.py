#-*- coding: utf-8 -*-

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import (
    MAIN_DISPATCHER,
    DEAD_DISPATCHER
)
from ryu.controller.handler import set_ev_cls

class NTPAmpMitigator(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(NTPAmpMitigator, self).__init__(*args, **kwargs)
