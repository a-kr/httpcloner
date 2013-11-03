#!/bin/bash -e
#
# ./clone_example.sh
#
# To setup your own traffic cloning project:
#
# 1. Copy and rename this file to my_project.sh (or something along these lines)
# 2. Change the PROJECT variable (see below)
# 3. Set IFACE and PCAP_FILTER variables to describe traffic source
# 4. Set DEST_HOST_PORT variable to describe traffic destination
# 5. If necessary, adjust traffic multipliers and limits
# 6. Optionally set STATSD variable to point to a statsd instance
# 7. Run: ./my_project.sh
#

# [ cmdline parameters ] ============================================
#
# number of replay servers (12 seems good for 5..15K RPS)
REPLAY_COUNT=12
# number of greenlet threads per replay server
THREADS=60

# string to insert in unix socket names to avoid conflicts with
# other traffic cloning projects
PROJECT=logger

# [ traffic source and destination, limits ] ==========================

# where is the traffic
IFACE=eth1

# what traffic should we clone
PCAP_FILTER='(dst net 192.168.7.96/27) && ((tcp dst port 80) || (tcp dst portrange 9090-9100))'

## How multiplying and limits work:
#
# sniffed traffic limited to L_PACKET_LIMIT ->
# -> HTTP requests ->
# -> multiplication by LISTENER_TRAFFIC_MULTIPLIER -> limit to L_HTTP_LIMIT ->
# -> multiplication by TRAFFIC_MULTIPLIER -> limit to REPLAY_RATE_LIMIT -> output

# multiply captured requests N times inside replay server
TRAFFIC_MULTIPLIER=1

# also multiplier, but inside the listener (not recommended)
LISTENER_TRAFFIC_MULTIPLIER=1

# who recieves cloned traffic
DEST_HOST_PORT=192.168.142.132:80

# limits on sniffing:
# IP packets per second
L_PACKET_LIMIT=100000
# HTTP requests per second (limited in listener)
L_HTTP_LIMIT=25000

# HTTP requests per second (limited in replay server; per replay server)
REPLAY_RATE_LIMIT=$((25000/$REPLAY_COUNT))

# extra params to pass to replay server
EXTRA_REPLAY_PARAMS=


# [ misc settings ] ==================================================
#
# size of backlog queue in the replay server, in requests
# (when it's full, requests are dropped)
BACKLOG=8000
# statsd host
STATSD=--statsd=192.168.142.31:8125

# base path for unix sockets (".#socket_number" suffix will be appended)
UNIX_SOCKET_PATH=/tmp/httpcloner.$PROJECT
# this file contains pids of all replay servers, one per line
FILE_WITH_PIDS=$PROJECT.pids

source clone.inc.sh
