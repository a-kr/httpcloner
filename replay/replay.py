#! coding: utf-8

from gevent import monkey
monkey.patch_all()

import os
import re
import sys
import logging
import socket
from optparse import OptionParser

import gevent
import gevent.queue
import time

import statsd
# https://github.com/gwik/geventhttpclient
try:
    import geventhttpclient.httplib as httplib
except ImportError:
    print >>sys.stderr, "could not import geventhttpclient, falling back to httplib"
    import httplib


logger = logging.getLogger()

statsd_client = None


class Counter(object):
    """ Считает число событий за последнюю секунду, умеет отправлять в statsd """
    def __init__(self, name=None):
        self.name = name
        self.v = 0
        self.t = int(time.time())

    def count(self):
        t = int(time.time())
        if t != self.t:
            if self.name:
                logger.info('C %s: %d per second', self.name, self.v)
                if statsd_client:
                    statsd_client.incr(self.name, self.v)
            self.on_tick()
            self.v = 1
            self.t = t
        else:
            self.v += 1

    def on_tick(self):
        pass


class Listener(object):
    """ Читает из датаграммного юникс-сокета и кладет в очередь.
        Следит за тем, чтобы очередь не переполнилась.
    """
    def __init__(self, i, unixsock, queue, options):
        self.i = i
        self.unixsock = unixsock
        self.queue = queue
        self.running = True
        self.options = options

    def next_query(self):
        pkt = self.unixsock.recv(16384)
        return pkt

    def runloop(self):
        i = self.i
        queue = self.queue
        multiplier = self.options.multiplier
        rate_limit = self.options.rate_limit
        location_grep = self.options.location_grep
        incoming_requests_counter = Counter('input')
        record_file = None
        if self.options.record_file:
            record_file = open(self.options.record_file, 'w')

        if statsd_client:
            def on_tick():
                statsd_client.incr('backlog', queue.qsize())

            incoming_requests_counter.on_tick = on_tick

        drop_counter = Counter('dropped')
        multiplied_output_counter = Counter()
        logger.info('Listener %d started', i)
        len_limit = self.options.backlog - self.options.backlog_breathing_space

        while self.running:
            q = self.next_query()
            if not q:
                continue
            if location_grep and not self.filter_by_location(q, location_grep):
                continue
            if record_file:
                print >>record_file, q
            incoming_requests_counter.count()
            logger.debug('Listener %d got %s', i, q)
            if queue:
                for _ in xrange(multiplier):
                    multiplied_output_counter.count()
                    if rate_limit > 0 and multiplied_output_counter.v >= rate_limit:
                        continue
                    if queue.qsize() > len_limit:
                        drop_counter.count()
                    else:
                        queue.put(q)

    def filter_by_location(self, q, location_grep):
        try:
            headers, _ = q.split('\r\n\r\n', 1)
            first_line = headers.split('\r\n', 1)[0]
            _, url, _ = first_line.split(' ', 2)
            if re.search(location_grep, url):
                return True
        except:
            logging.exception('parse error')
        return False


class Worker(object):
    """ Берет запрос из очереди, быстренько парсит и отправляет в апстрим по keepalive-соединению """
    def __init__(self, i, queue, output_counter, parse_errors_counter, options):
        self.i = i
        self.queue = queue
        self.output_counter = output_counter
        self.parse_errors_counter = parse_errors_counter
        self.running = True
        self.options = options

    def connect(self):
        conn = None
        if self.options.upstream:
            host, port = self.options.upstream, 80
            if ':' in host:
                host, port = host.split(':')
                port = int(port)
            conn = httplib.HTTPConnection(host, port)
            #conn = httplib.HTTPConnection(host, port)
        return conn

    def runloop(self):
        conn = self.connect()
        i = self.i
        queue = self.queue
        output_counter = self.output_counter
        parse_errors = self.parse_errors_counter
        logger.info('Worker %d started', i)
        methodset = set(['GET', 'POST', 'PUT', 'DELETE', 'HEAD'])
        only_get = self.options.only_get
        host_header = self.options.host_header
        location_prefix = self.options.location_prefix
        print_urls = self.options.print_urls

        while self.running:
            q = queue.get()
            if not q:
                continue
            try:
                headers, body = q.split('\r\n\r\n', 1)
                header_lines = headers.split('\r\n')
                method, url, _ = header_lines[0].split(' ', 2)
                if method not in methodset:
                    parse_errors.count()
                    continue

                if only_get and method != 'GET':
                    continue

                if location_prefix:
                    url = location_prefix + url

                if print_urls:
                    print >>sys.stderr, 'URL', url

                def split_lower_1(line):
                    parts = line.split(':', 1)
                    if len(parts) == 1:
                        return '', ''
                    a, b = parts
                    return a.lower(), b.strip()

                headers_dict_raw = dict(map(split_lower_1, header_lines))
                logger.debug([method, url])
                headers_dict = {}
                headers_dict['Content-Type'] = headers_dict_raw.get('content-type', 'text/plain')
                headers_dict['X-Real-IP'] = headers_dict_raw.get('x-real-ip', '127.0.0.1')
                if host_header == 'keep':
                    headers_dict['Host'] = headers_dict_raw.get('host', 'localhost')
                elif host_header:
                    headers_dict['Host'] = host_header
            except Exception as e:
                logger.exception('error whlie parsing request: %s %s', e, '')
                parse_errors.count()
                continue

            if not conn:
                try:
                    conn = self.connect()
                except Exception as e:
                    logger.exception('error whlie reconnecting: %s', e)

            if conn:
                try:
                    t0 = time.time()
                    conn.request(method, url, body, headers_dict)
                    r = conn.getresponse()
                    resp_data = r.read()
                    t1 = time.time()
                    statsd_client.timing('response_time', (t1 - t0) * 1000, rate=0.1)
                    if 400 <= r.status < 600 and statsd_client:
                        statsd_client.incr('response_%d' % r.status, rate=0.1)
                        logger.debug('response code %d: %s', r.status, resp_data)
                except Exception as e:
                    logger.debug('error whlie sending request: %s %s', e, q)
                    # force reconnect on next request
                    conn = None
                else:
                    output_counter.count()


def setup_options():
    parser = OptionParser()
    parser.add_option("--socket", dest="unix_socket", default="/tmp/mysock.dgram.0", action="store", help=u"path to unix seqpacket socket")
    parser.add_option("--threads", dest="threads", type=int, default=1, action="store", help=u"number of gevent threads")
    parser.add_option("--upstream", dest="upstream", default="", action="store", help=u"host:port to send HTTP requests to")

    parser.add_option("--multiplier", dest="multiplier", type=int, default=1, action="store", help=u"traffic multiplier")
    parser.add_option("--rate-limit", dest="rate_limit", type=int, default=0, action="store", help=u"output rate limit after multiplication, requests per second")

    parser.add_option("--only-GET", dest="only_get", default=False, action="store_true", help=u"forward only GET requests")
    parser.add_option("--location-prefix", dest="location_prefix", default="", action="store", help=u"prefix to add to URLs")
    parser.add_option("--location-grep", dest="location_grep", default="", action="store", help=u"replay only requests which match this regex")
    parser.add_option("--host-header", dest="host_header", default="", action="store", help=u"set host header")
    parser.add_option("--print-urls", dest="print_urls", default=False, action="store_true", help=u"print replayed urls to stderr")

    parser.add_option("--record-to-file", dest="record_file", default="", action="store", help=u"record requests to file")

    parser.add_option("--statsd", dest="statsd", default="", action="store", help=u"host:port of statsd")

    parser.add_option("--backlog", dest="backlog", type=int, default=30000, action="store", help=u"size of backlog queue")
    parser.add_option("--backlog-breathing-space", dest="backlog_breathing_space", type=int, default=500, action="store", help=u"backlog breathing space")

    parser.add_option("--loglevel", action="store", dest="loglevel", default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                      help=u"Уровень логгирования скрипта")
    return parser.parse_args()


def get_dgram_socket(addr):
    unixsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    unixsock.bind(addr)
    return unixsock


def main():
    global logger, statsd_client
    options, args = setup_options()
    logging.basicConfig(stream=sys.stdout, level=getattr(logging, options.loglevel), format="%(asctime)s :: %(message)s")
    logger = logging.getLogger()

    if os.path.exists(options.unix_socket):
        os.unlink(options.unix_socket)

    conn = get_dgram_socket(options.unix_socket)
    logger.info('spawning workers...')

    if options.statsd:
        host, port = options.statsd.split(':')
        prefix = 'gor.' + socket.gethostname().split('.')[0] + '.replay'
        statsd_client = statsd.StatsClient(host, int(port), prefix)

    total_output_counter = Counter('worker_output')
    parse_errors_counter = Counter('parse_errors')

    queue = gevent.queue.Queue(maxsize=options.backlog)

    listener = Listener(0, conn, queue, options)
    listener_thread = gevent.spawn(listener.runloop)
    workers = [Worker(i, queue, total_output_counter, parse_errors_counter, options) for i in xrange(options.threads)]
    threads = [gevent.spawn(worker.runloop) for worker in workers]
    listener_thread.join()

if __name__ == '__main__':
    main()
