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
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.GLOBAL_VARIABLE = 0
        self.GLOBAL_K_VALUE = 3
        self.generated_lsp = {}
        self.in_use_lsp = list()
        
    def is_edge_switch(self, src, switch, graph):
        succ_list = list()
        succ_list = graph.successors(src)
        if switch in succ_list:
            return True
        else:
            return False
        
    
    def out_switch(self, switch, graph):
        pred = list()
        pred = graph.predecessors(switch)
        return list(pred)
    
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
        switches=[dpid_prefix+ str(switch.dp.id) for switch in switch_list]
        graph.add_nodes_from(switches)
        
        #add bidirectional links to the topology 
        links_list = get_link(self.topology_api_app, None)
        #the links list contains a triplet indicating the src switch, the dst switch and the port through wich they communicate ----> VERY USEFUL!!!
        # ex. (1 , 2 , {'port' : 2}) --> this is not the real dpid, should be something like : 00:00:00:03
        links=[(dpid_prefix + str(link.src.dpid),dpid_prefix + str(link.dst.dpid),{'port':link.src.port_no}) for link in links_list]
        graph.add_edges_from(links)
        links=[(dpid_prefix + str(link.dst.dpid), dpid_prefix + str(link.src.dpid),{'port':link.dst.port_no}) for link in links_list]
        graph.add_edges_from(links)
        
        host_list = get_host(self.topology_api_app, None)
        host = [(h.mac, h.ipv4) for h in host_list]
        graph.add_nodes_from(host)
        for s in switch_list:
            h = get_host(self.topology_api_app, dpid = s.dp.id)
            h_link=list()
            h_link = [(dpid_prefix + s.dp.id, i.mac, {'port': i.port}) for i in h]
            graph.add_edges_from(h_link)
            h_link = [(i.mac, dpid_prefix + s.dp.id, {'port': i.port}) for i in h]
        return graph
   
    # Creation of all the paths and labels (paths from host to host)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        #Create the topology :
        #--> switch nodes are named 00:00:00:00:00:0{dpid_src}
        #--> host nodes are named with their MAC address
        #--> all links are bidirectional and contains an info on the port --> generic_link = (dpid_src, dpid_dst, {'port': port_no})
        self.net = self.build_graph(self.net)
        # Creation of K link disjoint paths from each host to each other host
        # Assign a label (starting from 1000 increasing by 1) to each of these paths
        lab = 1000
        for src in get_all_host(self):
            if self.net.has_node(src.mac):
                for dst in get_all_host(self):
                    if self.net.has_node(dst.mac):
                        if dst != src:
                            k_paths = self.k_shortest_paths(self.net, src, dst, self.GLOBAL_K_VALUE)
                            for pa in k_paths:
                                self.generated_lsp[pa] = lab
                                lab += 1
    
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
        dpid = datapath.id 
        if pkt.get_protocol(ipv4.ipv4):
            ipv4_header = pkt.get_protocol(ipv4.ipv4)     
            dst_ip = ipv4.dst
            src_ip = ipv4.src  
        
        if self.is_edge_switch(src_mac, dpid, self.net):
            # Edge switch --> label push
            possible_lsp = list()
            possible_label = list()
            for pa in self.generated_lsp.keys():
                if src_mac in pa and dst_mac in pa:
                    possible_lsp.append(pa)
                    possible_label.append(self.generated_lsp[pa])

            n = len(possible_lsp)
            k = random.randint(0, n -1)
            act_lab = possible_label[k]
            act_lsp = possible_lsp[k]
            #self.in_use_lsp.append(act_lsp)
            act_hop = act_lsp.index(src_mac)
            next_hop = act_lsp[act_hop + 1]
            outPo = self.net[act_hop][next_hop]['port']

            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            actions = [parser.OFPActionPushMpls(), parser.OFPActionSetField(mpls_label=act_lab), parser.OFPActionOutput(outPo)]
            self.add_flow(datapath, 10, match, actions)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=10, match=match, instructions=inst)
            datapath.send_msg(mod)
        else:
            # Middle stage switch
            for p in pkt.protocols:
                if isinstance(p, mpls.mpls):
                    act_lab = p.label
                    break
                else:
                    return
            for pa, lab in self.generated_lsp.items():
                if act_lab == lab:
                    act_lsp = pa
                    break
            for node in pa:
                if dpid == node:
                    actual_hop = pa.index(node)
                    next_hop = pa[actual_hop+1]
                    outPo = self.net[node][next_hop]['port']
                    break
            if next_hop != dst_mac:
                actions = [parser.OFPActionOutput(outPo)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, mpls_label = act_lab)
                self.add_flow(datapath, 10, match, actions)
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                actions)]
                mod = parser.OFPFlowMod(datapath=datapath, priority=10, match=match, instructions=inst)
                datapath.send_msg(mod)
                
                self.logger.info("Packet in switch %s with Source %s and Destination %s received at %s", dpid, src_mac, dst_mac, in_port)
                print(f"The chosen route on which forward the packet is {act_lsp} with label {act_lab}")
            else:
                actions = [parser.OFPActionPopMpls(), parser.OFPActionOutput(outPo)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, mpls_label = act_lab)
                self.add_flow(datapath, 10, match, actions)
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(datapath=datapath, priority=10, match=match, instructions=inst)
                datapath.send_msg(mod)
                self.logger.info("Packet reached Dst!!")

        
        
        
        
        



