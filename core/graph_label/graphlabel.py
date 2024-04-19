import networkx as nx
from core.graph_create import gfeature

class GraphLabel:

    def __init__():
        pass

    def graph_label(self, G: nx.Graph, node_indicator:str, att_indicitor:str, edge_indicitor:tuple, label:str):
        G_label = 0
        if label == '-   Malicious   C&C':
            # check whether containing specific C&C server Ip -- node
            if G.has_node(node_indicator):
                G_label = 1
                
        elif label == '-   Malicious   C&C-FileDownload':
            # check specific ip and resp bytes
            condition1 = G.has_edge(*edge_indicitor) and G.edges[edge_indicitor]['resp_bytes'] > 3
            condition2 = G.has_node(node_indicator)
            if condition1 and condition2:
                G_label = 2
        
        elif label == '-   Malicious   Attack':
            vul_ports = [37215, 52869, 8081, 666]
            # conn_state or the resp_p ---> vulnerable service
            for edge in G.edges(data=True):
                if 'S0' in G.edges[edge]['conn_state']:
                    G_label = 3
            for node in G.nodes:
                if node['label'] == 'resp ip' and len(list(set(node['port']) & vul_ports)) > 0:
                    G_label = 3

        elif label == '-   Malicious   DDoS':
            # count the edges between two nodes
            if gfeature.edges_count(G, edge_indicitor) > att_indicitor:
                G_label = 4
        else:
            print('Currently not support graph label with original label {}'.format(label))
            exit

        return G_label


