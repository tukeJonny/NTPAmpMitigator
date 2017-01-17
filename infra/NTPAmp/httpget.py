#-*- coding: utf-8 -*-
import sys
import time
import argparse
import logging
from decimal import Decimal

import requests
try:
    from requests.exceptions import ConnectTimeout
    MyTimeoutException=ConnectTimeout
except:
    from requests.exceptions import Timeout
    MyTimeoutException=Timeout
import matplotlib.pyplot as plt

class StaticGraph(object):
    def __init__(self, elapsed_times, timeout):
        self.elapsed = {
            'x': [x for x in range(1, len(elapsed_times)+1)],
            'y': elapsed_times
        }
        self.timeout = {
            'x': [x for x in range(1, len(elapsed_times)+1)],
            'y': [timeout]*len(elapsed_times)
        }

    def make(self):
        plt.title("Elapsed Times")
        plt.xlabel("time [sec]")
        plt.ylabel("elapsed time [sec]")
        plt.xlim([1,len(self.elapsed['x'])])
        plt.ylim([0,self.timeout['y'][0]+1])
        plt.yticks(0.1)
        plt.legend(loc='upper right')
        plt.grid()
        plt.plot(self.timeout['x'],self.timeout['y'], color='r')
        plt.plot(self.elapsed['x'],self.elapsed['y'])
        plt.savefig("elapsed.png")
        plt.show()

class Response(object):
    def __init__(self, url, elapsed, status_code):
        self.url = url
        if not isinstance(elapsed, int): #Not Error Number
            self._elapsed = elapsed.total_seconds()
        else:
            self._elapsed = elapsed
        self.status_code = status_code
        self.is_timeout = elapsed == 1 or status_code == 1

    @property
    def elapsed(self):
        return self._elapsed

    def __str__(self):
        if not self.is_timeout:
            msg = "[{status_code}] from {url}: Time= {elapsed}[sec]".format( \
                status_code=self.status_code,url=self.url,elapsed=self._elapsed)
        else:
            msg = "[!] from {url}: Request timeout"

        return msg

make_response = lambda d: Response(d['url'],d['elapsed'],d['status_code'])
class HTTPTest(object):
    """
    HTTP GET Tester
    """
    def __init__(self, url, count, timeout):
        self.url = url
        self.count = count
        self.timeout = timeout
        self.fail_count = 0

        self.elapsed_times = []

        self.INTERVAL = 1

        self.logger = logging.getLogger("HTTPTest")
        self.logger.setLevel(logging.DEBUG)
        handler = logging.FileHandler('http_get.log', mode='w')
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    @staticmethod
    def print_progress(s):
        sys.stdout.write('\r'+s)
        sys.stdout.flush()

    def do_get(self):
        """
        Do HTTP GET with requests module.
        """
        try:
            res = requests.get(self.url, timeout=self.timeout)
            response = make_response(res.__dict__)
            self.elapsed_times.append(response.elapsed)
            self.logger.info( str(response) )
        except MyTimeoutException:
            response = make_response({'url':self.url,'elapsed':-1,'status_code':-1})
            self.elapsed_times.append(self.timeout)
            self.logger.info( str(response) )
            self.fail_count += 1

    def display_statics(self):
        pktloss_ratio = Decimal(str((self.fail_count/self.count)))*Decimal('100')
        self.logger.info("+++++ HTTP GET Tester Statics +++++")
        self.logger.info("Send: {}".format(self.count))
        self.logger.info("Recv: {}".format(self.count-self.fail_count))
        self.logger.info("Loss: {}".format(self.fail_count))
        self.logger.info("{}% Packet Loss".format(pktloss_ratio))
        self.logger.info("+++++++++++++++++++++++++++++++++++")

        # Make static graph images
        statgraph = StaticGraph(self.elapsed_times, self.timeout)
        statgraph.make()

    def start(self):
        """
        call do_get <self.count> time.
        """
        self.logger.info("[+] Start {} times HTTP GET Test to {}!".format(self.count, self.url))
        for i in range(self.count):
            self.do_get()
            time.sleep(self.INTERVAL)
            self.print_progress("{}%".format((i/self.count)*100))
        self.display_statics()

def parse_argument():
    parser = argparse.ArgumentParser(description='ping like HTTP GET tester.')
    parser.add_argument("-u", "--url", type=str, help='Request to this url.', default="http://www.yahoo.co.jp/")
    parser.add_argument("-c", "--count", type=int, help='HTTP GET test count.', default=3)
    parser.add_argument("-t", "--timeout", type=int, help='Request timeout limit.', default=5)
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = parse_argument()
    tester = HTTPTest(args.url, args.count, args.timeout)
    tester.start()