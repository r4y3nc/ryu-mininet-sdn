from __future__ import print_function

from ryu.lib.packet import packet as pkt_lib
from ryu.lib.packet import tcp, icmp


class IPHandler(object):

    def __init__(self, vip, lb_mac, server_pool, firewall, balancer, logger=None):
        self.VIP         = vip
        self.LB_MAC      = lb_mac
        self.SERVER_POOL = server_pool
        self.firewall    = firewall
        self.balancer    = balancer
        self.logger      = logger

    def handle_forward(self, datapath, in_port, raw_data, ip_pkt):
        from policy import is_allowed_to_vip

        src_ip = ip_pkt.src

        if self.logger:
            self.logger.info("----------------------------------")
            self.logger.info("Request dari client : %s", src_ip)

        if self.firewall.cek_ddos(src_ip):
            if self.logger:
                self.logger.warning(
                    "Request dari %s ditolak oleh firewall", src_ip
                )
            return True

        parsed   = pkt_lib.Packet(raw_data)
        tcp_pkt  = parsed.get_protocol(tcp.tcp)
        icmp_pkt = parsed.get_protocol(icmp.icmp)

        if not is_allowed_to_vip(src_ip, tcp_pkt, icmp_pkt):
            if self.logger:
                self.logger.warning(
                    "[POLICY VIP] Diblokir: %s tidak boleh akses VIP dengan protokol ini",
                    src_ip
                )
            return True

        if self.logger:
            self.logger.info("Firewall : traffic normal")

        server_ip   = self.balancer.pilih_server()
        server_info = self.balancer.get_server_info(server_ip)

        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        actions = [
            parser.OFPActionSetField(eth_dst=server_info["mac"]),
            parser.OFPActionSetField(ipv4_dst=server_ip),
            parser.OFPActionOutput(server_info["port"]),
        ]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=raw_data,
        )
        datapath.send_msg(out)
        return True

    def handle_reverse(self, datapath, in_port, raw_data, ip_pkt):
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        actions = [
            parser.OFPActionSetField(eth_src=self.LB_MAC),
            parser.OFPActionSetField(ipv4_src=self.VIP),
            parser.OFPActionOutput(ofproto.OFPP_FLOOD),
        ]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=raw_data,
        )
        datapath.send_msg(out)
        return True