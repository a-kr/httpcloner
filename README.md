httpcloner
==========

High-performance HTTP traffic sniffing / replaying / cloning tool, heavily inspired by Gor (https://github.com/buger/gor)


Requirements
------------

* gcc >= 4.6.3
* libpcap, libpcap-dev, libevent-dev
* python 2.7
* python packages:
    * gevent
    * statsd
    * https://github.com/gwik/geventhttpclient (can fall back to built-in httplib if unavailable)

