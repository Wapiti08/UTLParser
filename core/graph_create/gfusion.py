'''
 # @ Author: Newt Tan
 # @ Create Time: 2024-03-04 10:02:15
 # @ Modified by: Newt Tan
 # @ Modified time: 2024-03-06 11:20:12
 # @ Description: Potential Fusion Part or Optimization Part to reduce the graph size or 
                achieve the fusion of graphs from diverse data sourcesw
 '''
import networkx as nx
from datetime import datetime, timedelta

class GraphFusion:
    ''' the module to fuse mutiple sub graphs and extract precise temporal graph
    
    '''
    def __init__(self, avg_len:int, pre_long_len:int):
        '''
        :param avg_len: the average length of path in termporal graph
        :param pre_long_len: the pre-defined potential longest path length
        '''
        self.avg_len = avg_len
        self.pre_long_len = pre_long_len

    def graph_conn(self, graph_list:list):
        ''' fuse multiple sub graphs according to rule information like auth, audit, dns, access 
        :param graph_list: the list of graphml --- sub graphs
        '''
        return nx.compose_all(graph_list)

    def temp_graph(self, G:nx.classes.digraph.DiGraph, T:str, threshold: int):
        '''
        :param G: the original fused multi-edge directed graph
        :param T: the timestamp to pick up temporal graph
        '''
        # calculate the time interval
        min_time, max_time = self.time_scope(T, threshold)
        time_format = "%Y-%b-%d %H:%M:%S.%f"
        temp_graph = nx.MultiDiGraph()
        for u, v, edge in G.edges(data=True):
            # extract the attribute element
            if datetime.strptime(edge['timestamp'], time_format) >=min_time and \
                 datetime.strptime(edge['timestamp'], time_format) <=max_time :
                temp_graph.add_edge(u,v, **edge)
        # print("The temporal graph at timestamp {} is".format(T))
        return temp_graph

    def choose_thres(self, G, T:str, thres_list: list):
        '''
        :param G: the fused (composed) graph
        :param thres_list: the defined potential threshold list for time interval
        '''
        delay_score_dict = {}
        delay_score = 0
        for thres in thres_list:
            t_graph = self.temp_graph(G, T, thres)
            delay_score = self.inde_score(t_graph) + self.inde_score(t_graph)
            delay_score_dict[thres] = delay_score
        # pick the keys with largest value
        max_value = max(delay_score_dict.values())
        max_keys = [k for k, v in delay_score_dict.items() if v == max_value]
        return min(max_keys)

    def time_scope(self, T: str, threshold:int):
        ''' calculate the datetime scope according to threshold
        
        '''
        time_format = "%Y-%b-%d %H:%M:%S.%f"
        timestamp = datetime.strptime(T, time_format)
        min_time = timestamp - timedelta(seconds=threshold)
        max_time = timestamp + timedelta(seconds=threshold)
        return min_time, max_time

    def inte_score(self, G):
        ''' calculate the score to measure the integrity of sub graphs ---- extracted temporal graphs
        :param G: the picked temporal graph
        '''
        inte_score = 0
        # get the longest path and its length
        longest_path = max(nx.connected_components(G))
        longest_len = len(longest_path)
        # get central node and its degree
        cen_node = nx.center(G)
        node_degree = G.degree(cen_node)
        if longest_len >= self.avg_len and longest_len <= self.pre_long_len + 1:
            inte_score += 1
        if node_degree>=2 and node_degree<=3:
            inte_score += 1
        return inte_score

    def inde_score(self, G):
        ''' calcuate the score to measure the independence of sub graphs
        :param G: the picked temporal graph
        '''
        inde_score = 0
        three_paths = []
        # find all paths with length 2
        for u in G.nodes():
            for v in G.nodes():
                if u != v:
                    paths = nx.all_simple_paths(G, u, v, cutoff=2)
                    for path in paths:
                        # path with length 2 has 3 nodes
                        if len(path) == 3:
                            three_paths.append(path)
        # check the homogeneity and heterogeneity
        for t_path in three_paths:
            if t_path[-1] in t_path[0:-1]:
                inde_score += 1
        return inde_score
            

