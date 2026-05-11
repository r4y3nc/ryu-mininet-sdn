from mininet.topo import Topo

class Topology(Topo):
  def build(self):
    switches = {s: self.addSwitch(s) for s in ['s1', 's2', 's3']}

    host_configs = [
      ('web1', '11', '11', 's1'),
      ('web2', '12', '12', 's1'),
      ('web3', '13', '13', 's1'),
      ('dev1', '21', '21', 's2'),
      ('dev2', '22', '22', 's2'),
      ('user1', '31', '31', 's3'),
      ('user2', '32', '32', 's3'),
    ]

    for name, ip_suf, mac_suf, sw in host_configs:
      h = self.addHost(
        name,
        ip=f'10.0.1.{ip_suf}/24',
        mac=f'00:00:00:00:01:{mac_suf}'
      )
      self.addLink(h, switches[sw])
    
    self.addLink(switches['s2'], switches['s1'])
    self.addLink(switches['s3'], switches['s1'])

topos = {'topology': (lambda: Topology())}