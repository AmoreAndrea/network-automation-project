from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology.api import get_switch, get_link, get_host, get_all_host
import networkx as nx
from ryu.topology import event, switches 
from ryu.app.ofctl.api import get_datapath
from ryu.lib.packet import packet
import random
import logging
from webob import Response 
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import ethernet, mpls
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ether
from ryu.app.ofctl.api import get_datapath


class MplsControllerSmart(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MplsControllerSmart, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mac_to_dpid = {}
        self.port_to_mac = {}
        self.port_occupied = {}
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.GLOBAL_VARIABLE = 0
        self.GLOBAL_K_VALUE = 3
        self.in_use_lsp = {}
        
    def is_edge_switch(self, src, dpid_src, inport):
        for host in get_all_host(self):
            if host.mac == src and host.port.dpid == dpid_src and host.port.port_no == inport:
                return True
            else:
                return False
        
    
    def out_switch(self, dst_mac):
        for host in get_all_host(self):
            if host.mac == dst_mac:
                return (host.port.dpid, host.port.port_no)
        return(None, None)
    
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
    def build_graph(self, graph):
        dpid_prefix = "00:00:00:00:00:0"
        switch_list = get_switch(self.topology_api_app, None)   
        switches=[switch.dp.id for switch in switch_list]
        if self.GLOBAL_VARIABLE == 0:
            # Probably need to look for these ports to correctly match the out and in port
            for id_,s in enumerate(switches):
                for switch_port in range(1, len(switch_list[id_].ports)):
                    self.port_occupied.setdefault(s, {})
                    self.port_occupied[s][switch_port] = 0
        print("Occupied port :  ", self.port_occupied)
        graph.add_nodes_from(switches)
        print("Switches : ", switches)
        
        #add bidirectional links to the topology 
        links_list = get_link(self.topology_api_app, None)
        #the links list contains a triplet indicating the src switch, the dst switch and the port through wich they communicate ----> VERY USEFUL!!!
        # ex. (1 , 2 , {'port' : 2}) --> this is not the real dpid, should be something like : 00:00:00:00:00:01
        links=[(links.src,links.dst,{'port':link.src.port_no}) for link in links_list]
        print("Links : ",links)
        graph.add_edges_from(links)
        links=[(links.dst, links.src,{'port':link.dst.port_no}) for link in links_list]
        graph.add_edges_from(links)
        links_=[(link.dst.dpid,link.src.dpid,link.dst.port_no) for link in links_list]
        for l in links_:
            self.port_occupied[l[0]][l[2]] = 1

        return graph
    
    def find_next_hop_port(self, graph, path, dpid):
        for node in path:
            if node == dpid:
                actual_hop = path.index(node)
                break
        next_hop = actual_hop + 1
        link = graph[path[actual_hop]][path[next_hop]]
        return link['port']

   
    # Creation of all the paths and labels (paths from host to host)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.net = self.build_graph(self.net)
        

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
    
    

                    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]  
        dst_mac = eth.dst
        src_mac = eth.src
        dpid_src = datapath.id 
        if pkt.get_protocol(ipv4.ipv4):
            ipv4_header = pkt.get_protocol(ipv4.ipv4)     
            dst_ip = ipv4.dst
            src_ip = ipv4.src  
        dst_switch, dst_port = self.out_switch(dst_mac)
        
        if self.is_edge_switch(src_mac, dpid_src, in_port):
            self.logger.info("Packet in switch: %s, From the port: %s", dpid_src, in_port)
            k_paths = self.k_shortest_paths(self.net, dpid_src, dst_switch, self.GLOBAL_K_VALUE)
            k = len(k_paths)
            lsp = k_paths[random.randint(0, k-1)]
            lab = 1000
            if lsp in self.in_use_lsp.keys() and lab in self.in_use_lsp.values():
                lsp = k_paths[random.randint(0, k-1)]
                lab += 1
            self.in_use_lsp[lsp] = lab
            outPo = self.find_next_hop_port(self.net, lsp, dpid_src)
            print(f"The packet received from {dpid_src} is routed with label {lab} in the LSP {''.join(lsp)}")
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            actions = [parser.OFPActionPushMpls(), parser.OFPActionSetField(mpls_label=lab), parser.OFPActionOutput(outPo)]
            self.add_flow(datapath, 10, match, actions)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=10, match=match, instructions=inst)
            datapath.send_msg(mod)
            return
        
        elif dpid_src != dst_switch and not self.is_edge_switch(src_mac, dpid_src, in_port):
            self.logger.info("Packet in switch: %s, From the port: %s", dpid_src, in_port)
            # Middle stage switch
            for p in pkt.protocols:
                if isinstance(p, mpls.mpls):
                    lab = p.label
                    break
            for pa,label in self.in_use_lsp.items():
                if lab == label:
                    lsp = pa
                    break
            outPo = self.find_next_hop_port(self.net, lsp, dpid_src)
            print(f"The packet is inside the MPLS network routed with label {lab} on the LSP {lsp}")
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, mpls_label = lab)
            actions = [parser.OFPActionOutput(outPo)]
            self.add_flow(datapath, 10, match, actions)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=10, match=match, instructions=inst)
            datapath.send_msg(mod)
            return
        
        else:
            # Destination switch reached
            self.logger.info("Packet in switch: %s, From the port: %s", dpid_src, in_port)
            for p in pkt.protocols:
                if isinstance(p, mpls.mpls):
                    lab = p.label
                    break
            for pa,label in self.in_use_lsp.items():
                if lab == label:
                    lsp = pa
                    break
            outPo = dst_port
            actions = [parser.OFPActionOutput(outPo)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, mpls_label = lab)
            self.add_flow(datapath, 10, match, actions)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=10, match=match, instructions=inst)
            datapath.send_msg(mod)
            print(f"The packet routed on the LSP {''.join(lsp)} with label {lab} is leaving the MPLS network")
            return








        
        
        
        
        
        



