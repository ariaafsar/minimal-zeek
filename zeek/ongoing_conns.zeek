module OngoingConn;

export {
    redef enum Log::ID += { LOG_ONGOING_CONN };

    type Info: record {
        uid: string &log;
        ts: time &log;

        orig_h: addr &log;
        orig_p: port &log;
        resp_h: addr &log;
        resp_p: port &log;

        orig_bytes: count &log;
        resp_bytes: count &log;
        orig_pkts: count &log;
        resp_pkts: count &log;
    };
}

const SNAPSHOT_INTERVAL = 7200sec;
global active_conns: table[string] of connection;

event snapshot()
{
    for ( uid in active_conns )
    {
        local c = active_conns[uid];

        Log::write(LOG_ONGOING_CONN, [
            $uid = c$uid,
            $ts  = network_time(),

            $orig_h = c$id$orig_h,
            $orig_p = c$id$orig_p,
            $resp_h = c$id$resp_h,
            $resp_p = c$id$resp_p,

            $orig_bytes = c$orig$size,
            $resp_bytes = c$resp$size,
            $orig_pkts  = c$orig$num_pkts,
            $resp_pkts  = c$resp$num_pkts
        ]);
    }

    schedule SNAPSHOT_INTERVAL { snapshot() };
}

event zeek_init()
{
    Log::create_stream(LOG_ONGOING_CONN,
        [$columns = Info, $path = "ongoing_conns"]);

    schedule SNAPSHOT_INTERVAL { snapshot() };
}

event new_connection(c: connection)
{
    active_conns[c$uid] = c;
}

event connection_state_remove(c: connection)
{
    delete active_conns[c$uid];
}

