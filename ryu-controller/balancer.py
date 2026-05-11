from __future__ import print_function

import time


class LeastConnectionBalancer(object):
    
    CONNECTION_TIMEOUT = 5

    def __init__(self, server_pool, logger=None):
        self.SERVER_POOL = server_pool
        self.server_list = list(server_pool.keys())
        self.logger      = logger

        self.conn_times = {ip: [] for ip in self.server_list}

    def _active_count(self, server_ip):
        now = time.time()
        self.conn_times[server_ip] = [
            t for t in self.conn_times[server_ip]
            if now - t < self.CONNECTION_TIMEOUT
        ]
        return len(self.conn_times[server_ip])

    def _snapshot(self):
        return {ip: self._active_count(ip) for ip in self.server_list}

    def pilih_server(self):
        snapshot = self._snapshot()

        server_ip = min(self.server_list, key=lambda ip: snapshot[ip])

        self.conn_times[server_ip].append(time.time())
        snapshot[server_ip] += 1

        if self.logger:
            self.logger.info(
                "[LOAD BALANCER] Memilih server : %s | koneksi aktif -> %s",
                server_ip,
                snapshot
            )

        return server_ip

    def get_server_info(self, server_ip):
        return self.SERVER_POOL[server_ip]

    def get_stats(self):
        return self._snapshot()