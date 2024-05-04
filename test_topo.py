import mininet
from mininet.topo import Topo

class myTopo (Topo):
    def build(self):
        
        #Add hosts and switches
        host_1 = self.addHost('h1')
        host_2 = self.addHost('h2')
        host_3 = self.addHost('h3')
        switch_1 = self.addSwitch('s1')
        switch_2 = self.addSwitch('s2')
        switch_3 = self.addSwitch('s3')
        switch_4 = self.addSwitch('s4')
        switch_5 = self.addSwitch('s5')
        switch_6 = self.addSwitch('s6')
        
        #Add links
        self.addLink(host_1, switch_1)
        self.addLink(host_2, switch_2)
        self.addLink(host_3, switch_5)
        self.addLink(host_3, switch_6)
        self.addLink(switch_1, switch_2)
        self.addLink(switch_1, switch_4)
        self.addLink(switch_2, switch_3)
        self.addLink(switch_1, switch_3)
        self.addLink(switch_2, switch_4)
        self.addLink(switch_4, switch_5)
        self.addLink(switch_4, switch_6)
        self.addLink(switch_3, switch_5)
        self.addLink(switch_3, switch_6)
        self.addLink(switch_5, switch_6)
        
topos = {'mytopo' : (lambda : myTopo ())}
