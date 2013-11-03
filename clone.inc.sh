# default variable values

if [[ -z "$REPLAY_RATE_LIMIT" ]]
then
    REPLAY_RATE_LIMIT=0
fi

# general functions for traffic cloning setup

function kill_old_replays() {
    if [ -f $FILE_WITH_PIDS ]
    then
        set +e
        cat $FILE_WITH_PIDS | xargs kill
        set -e
    fi
}

function start_replays() {
    echo "staring #<$REPLAY_COUNT> replay servers with #<$THREADS> threads and backlog of size #<$BACKLOG>"

    rm -f $FILE_WITH_PIDS

    for (( i=0; i <= $(($REPLAY_COUNT-1)); i++ ))
    do
        echo "start replay server $i"
        python replay/replay.py $STATSD \
            --socket="$UNIX_SOCKET_PATH.$i" \
            --threads $THREADS --backlog $BACKLOG \
            --multiplier $TRAFFIC_MULTIPLIER \
            --rate-limit $REPLAY_RATE_LIMIT \
            --upstream "$DEST_HOST_PORT" $EXTRA_REPLAY_PARAMS $REPLAY_EXTRA_PARAMS > /dev/null &
        REPLAY_PID=$!
        echo $REPLAY_PID >>$FILE_WITH_PIDS
        echo "pid = $REPLAY_PID started"
    done

    ps ax | grep "python replay" | wc -l
}

function start_cap() {
    sleep 1  # giving Python processes time to start listening on unix sockets
    echo "starting cap"
        ./csniffer/cap $STATSD -i$IFACE --filter="$PCAP_FILTER" \
            --rpslimit=$L_HTTP_LIMIT --replay-socket=$UNIX_SOCKET_PATH \
            --pool-size=$REPLAY_COUNT --multiply=$LISTENER_TRAFFIC_MULTIPLIER
}

kill_old_replays
start_replays
start_cap
