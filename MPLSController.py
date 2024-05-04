import ryu
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_link, get_host, get_all_host
from ryu.topology import event, switches 
import networkx as nx
import json
import logging
import struct
import random
from webob import Response
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ether
from ryu.app.ofctl.api import get_datapath


class MplsController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MplsController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mac_to_dpid = {}
        self.port_to_mac = {}
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.port_occupied = {}
        self.GLOBAL_VARIABLE = 0
        self.GLOBAL_K_VALUE = 3
        self.hosts = {}
        self.used_lsp={}
        
        
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)



#K Disjoint Path algorithm
#Function to find all simple path and then sort them in length order
    # WORKS
    def find_paths(self, graph, source, target):
        all_paths = nx.all_simple_paths(graph, source, target)
        
        # Convert paths to a list and sort them by length
        sorted_paths = sorted(all_paths, key=lambda x: len(x))
        paths = list()
        for pa in sorted_paths:
            paths.append(pa)
        #return a list containing all sorted paths (from the shortest)
        return paths 
             
    
    # WORKS
    def select_link_disjoint_paths(self, graph, source, target):
        # Find all possible simple paths
        paths = self.find_paths(graph, source, target)
        count = 0
        # Filter paths to ensure link disjointness and return the first k paths
        link_disjoint_paths = list()
        for pa in paths:
            edge_set = set(zip(pa[:-1], pa[1:]))  # Create a set of edges for the current path
            if not link_disjoint_paths or all(edge_set.isdisjoint(set(zip(p[:-1], p[1:]))) for p in link_disjoint_paths):
                link_disjoint_paths.append(pa)
                count += 1     
        #Return a list of link disjoint paths
        print(f"There are {count} available link-disjoint paths")
        return link_disjoint_paths 
    
    #Returns the k-shortest paths available (or less than k if there are less available)
    # WORKS
    def k_shortest_paths(self, graph, source, target, k):
        label_set = list()
        label_set = self.select_link_disjoint_paths(graph, source, target)
        #label_set is a list of list, each one containing the switches which define an LSP
        #Only considers the shortest path in term of hops
        min = 100
        for lab in label_set:
            if len(lab) < min:
                min = len(lab)
        for lab in label_set:
            if len(lab) > min:
                label_set.remove(lab)
        if len(label_set) < k:
            print(f"There are {len(label_set)} shortest path, not K!!")
            return label_set
        else:
            nb_pa = len(label_set)
            k_shortest_path = list()
            for i in range(k):
                k_shortest_path.append(label_set[i])
            print(f"{nb_pa} shortest path have been found, only the first {k} will be considered")
            return k_shortest_path

    #Used to find out if an end-point have only one connection to the MPLS network
    def is_choking(host_list, host):
        host_onn = 0
        for h in host_list:
            if h.mac == host:
                host_conn = len(h)
                break
        if host_conn == 1:
            return True
        else:
            return False
            
            
    # We need to find out the edge switch which connects host to the MPLS network ---> used for 1 link host found in is_choking
    def edge_switches(host, link_list):
        count = 0
        for l in link_list:
            if l[0] == host:
                edge_switch = l[1]
                break
        return edge_switch
            
        
        
        
        
        
        
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore ipv6 packet
            return

        dst = eth.dst
        src = eth.src
        #id (mac?) of the switch processing the actual pkt
        dpid_src = datapath.id

        ip_h = pkt.get_protocols(ipv4.ipv4)
        if ip_h:
            src_ip = ip_h.src
            dst_ip = ip_h.dst

        self.hosts[src] = {'ip' : src_ip, 'mac' : src}   
        self.hosts[dst] = {'ip' : dst_ip, 'mac' : dst}  

        #MAC LEARNING

        self.mac_to_port.setdefault(dpid_src, {})
        self.port_to_mac.setdefault(dpid_src, {})
        #a pkt incoming from the src thìo this dpid (whichever it is) is coming through port == in_port
        self.mac_to_port[dpid_src][src] = in_port
        #a pkt incoming from the src (recognized by the MAC addr) 
        self.mac_to_dpid[src] = dpid_src
        #a pkt incoming at port = in_port in dpid is coming from the source
        self.port_to_mac[dpid_src][in_port] = src


        # TOPOLOGY DISCOVERY------------------------------------------
        switch_list = get_switch(self.topology_api_app, None)   
        switches=[switch.dp.id for switch in switch_list]

        if self.GLOBAL_VARIABLE == 0:
            for id_,s in enumerate(switches):
                for switch_port in range(1, len(switch_list[id_].ports)):
                    self.port_occupied.setdefault(s, {})
                    self.port_occupied[s][switch_port] = 0
        self.net.add_nodes_from(switches)

        #add bidirectional links to the topology 
        lls = list()
        links_list = get_link(self.topology_api_app, None)
        #the links list contains a triplet indicating the src switch, the dst switch and the port through wich they communicate ----> VERY USEFUL!!!
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        for l in links:
            lls.append(l)
        print(lls)
        self.net.add_edges_from(links)
        links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
        for l in links:
            lls.append(l)
        self.net.add_edges_from(links)
        links_=[(link.dst.dpid,link.src.dpid,link.dst.port_no) for link in links_list]
        for l in links_:
            self.port_occupied[l[0]][l[2]] = 1
            
        # Add the host nodes in the network and connect them in the networkx graph (necessary for k path algorithm)
        host_list = get_host(self.topology_api_app, None)   
        hosts = [host.mac for host in host_list]
        self.net.add_nodes_from(hosts)
        h_links = [(host.mac, host.dpid, {'port': host.port_no}) for host in host_list]
        self.net.add_edges_from(h_links)
        h_links = [(host.dpid, host.mac, {'port': host.port_no}) for host in host_list]
        self.net.add_edges_from(h_links)
 
        # Here i have to find out which case i am considering
        # By doing so, i select from where and to where start considering the path
        if self.is_choking(src) and self.is_choking(dst):
            start = self.edge_switches(src, h_links)
            target = self.edge_switches(dst, h_links)
        elif self.is_choking(src) and not self.is_choking(dst):
            start = self.edge_switches(src, h_links)
            target = dst
        elif not self.is_choking(src) and self.is_choking(dst):
            start = src
            target = self.edge_switch(dst)
        else:
            start = src
            target = dst 
            
            
        # Discover of LER switches -----> may want to consider the case of multiple LERs in one or both side of the MPLS network
        if dpid_src == start or dpid_src == self.net.successors(start):
            #Generation of k_disjoint paths between the two LER
            # Select one path randomly
            k_paths = self.k_shortest_paths(self.net, start, target, self.GLOBAL_K_VALUE)
            k = len(k_paths)
            lsp = k_paths[random.randint(0, k -1)]
            lsp_prio = random.randint(0,30)
            
            # This is used at the edge switch in order to use always different paths for each packet entering the MPLS netwwork
            # After 10 iteration we re-use an already used LSP in order to avoid infinte loops
            i = 0
            while lsp in self.used_lsp.keys() and i < 10:
                lsp = k_paths[random.randint(0, k -1)]  
                i += 1              
            # Find the actual position in the LSP and the next hop with the corresponding port
            for hop in lsp:
                if dpid_src == hop:
                    actual_hop = lsp.index(hop)
            next_hop = lsp[actual_hop + 1]
            for l in lls:
                if next_hop == l[1] and dpid_src == l[0]:
                    outPo = l[2].values
                    break     
            self.used_lsp.append[lsp] = lsp_prio
            self.logger.info("Packet in switch: %s, source IP: %s, destination IP: %s, From the port: %s", dpid_src, src_ip, dst_ip, in_port)
            print(f"The received packet is routed through the LSP {''.join(lsp)}")
            # Now that we know the outPort and the next hop, we can add a flow rule forcing the routing to the next switch in the LSP 
            actions = [parser.OFPActionOutput(outPo)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            
            #Since we select randomly the LSP it is probable that the flow match is not working good
            self.add_flow(datapath, lsp_prio, match, actions)     
            
            # Now we tell the switch what to do with a Packet Out
            out = parser.OFPPacketOut(datapath=datapath,
                                buffer_id=ofproto.OFP_NO_BUFFER,
                                in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                                data=msg.data)
            datapath.send_msg(out)
        # Here i have to check if the switch is a middle switch, hence neither a path start nor the edge switch to exit the MPLS network
        # For sure it is not the edge switch to enter the MPLS network
        elif target == dst and dpid_src != self.net.predecessors(target) or target != dst and dpid_src != target:
            # the packet is in a middle switch so we need to consider the actual in use LSP
            
            # We find the previous hop
            for l in lls:
                if l[0] == dpid_src and l[2].values == in_port:
                    previous_hop = l[1]
            # Here we find the actual LSP in use for the packet
            for pa in self.used_lsp.keys():
                if dpid_src in pa and previous_hop in pa and pa.index(dpid_src) == (pa.index(previous_hop) + 1):
                    current_lsp = pa
                    actual_hop = pa.index(dpid_src)
                    break
            prio = self.used_lsp[current_lsp]
            next_hop = current_lsp[actual_hop + 1]
            # Here we find the out port where to send the packet (along the lsp)
            for l in lls:
                if next_hop == l[1] and dpid_src == l[0]:
                    outPo = l[2].values
                    break
            self.logger.info("Packet in switch: %s, source IP: %s, destination IP: %s, From the port: %s", dpid_src, src_ip, dst_ip, in_port)
            print(f"The received packet is routed through the LSP {''.join(current_lsp)}")
            # Now that we know the outPort and the next hop, we can add a flow rule forcing the routing to the next switch in the LSP 
            actions = [parser.OFPActionOutput(outPo)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            
            #Since we select randomly the LSP it is probable that the flow match is not working good
            self.add_flow(datapath, prio, match, actions)     
            
            # Now we tell the switch what to do with a Packet Out
            out = parser.OFPPacketOut(datapath=datapath,
                                buffer_id=ofproto.OFP_NO_BUFFER,
                                in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                                data=msg.data)
            datapath.send_msg(out)
        # We need now to implement the behavior in case the middle switch reached is directly connected to the destination inside the else: up here
        else:
            for l in lls:
                if l[0] == dpid_src and l[2].values == in_port:
                    previous_hop = l[1]
            # Here we find the actual LSP in use for the packet
            for pa in self.used_lsp.keys():
                if dpid_src in pa and previous_hop in pa and pa.index(dpid_src) == (pa.index(previous_hop) + 1):
                    current_lsp = pa
                    actual_hop = pa.index(dpid_src)
                    break
            prio = self.used_lsp[current_lsp]
            # Case in which the actual hop is the edge switch and dpid_src == target
            if actual_hop == len(current_lsp) - 1 and current_lsp[actual_hop] != dst:
                next_hop  = dst
                for l in h_links:
                    if next_hop == l[1] and dpid_src == l[0]:
                        outPo = l[2].values
                        break
            # Case in which the edge switch is the actual hop and dst == target
            else:
                next_hop = current_lsp[actual_hop + 1]
            # Here we find the out port where to send the packet (along the lsp)
                for l in lls:
                    if next_hop == l[1] and dpid_src == l[0]:
                        outPo = l[2].values
                        break
            print(f"The received packet is routed through the LSP {''.join(current_lsp)} to the {dst} and is leaving the MPLS network")
            # Now that we know the outPort and the next hop, we can add a flow rule forcing the routing to the next switch in the LSP 
            actions = [parser.OFPActionOutput(outPo)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            
            #Since we select randomly the LSP it is probable that the flow match is not working good
            self.add_flow(datapath, prio, match, actions) 
            
            
            
        
        