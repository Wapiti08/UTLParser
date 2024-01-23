""" 
@Description: 
@Author: newt.tan 
@Date: 2024-01-23 16:14:32 
@Last Modified by:   newt.tan  
@Last Modified time: 2024-01-23 16:14:32  
"""

def graph_from_structure_data(bro_log_file: str):
    ''' build graph from structured logs --- consider ips and ports only

    node value: id.orig_h, id.resp_h
    node attributes: id.orig_p, id.resp_p
    edge attributes: ts, resp_bytes, conn_state
    
    '''
    log_to_df = LogToDataFrame()
    # keep the ts column
    conn_df = log_to_df.create_dataframe(bro_log_file,ts_index=False)
    # extract the initial desired features
    field_list = ['ts', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'resp_bytes', 'conn_state']
    # for testing
    fea_df = conn_df[field_list][:100]
    G = nx.MultiDiGraph()
    for _, row in tqdm(fea_df.iterrows(), desc='parsing logs to graphs'):
        # edges = []
        # add node with its attribute
        # if G.has_node(row['id.orig_h']):

        G.add_node(row['id.orig_h'], label='orig ip', port=row['id.orig_p'])
        
        G.add_node(row['id.resp_h'], label='resp ip', port=row['id.resp_p'])
        # G.nodes[row['id.resp_h']]['port'].append(row['id.resp_p'])
        # add edge
        G.add_edge(row['id.orig_h'], row['id.resp_h'], label=row['ts'], resp_bytes=row['resp_bytes'], conn_state=row['conn_state'])
    
    # split into connected graphs
    graphs = list(nx.strongly_connected_components(G))
    print("there are {} full connected graphs from {}".format(len(graphs), bro_log_file))
    return G

def graph_label(G: nx.Graph, node_indicator:str, att_indicitor:str, edge_indicitor:tuple, label:str):
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
        if edges_count(G, edge_indicitor) > att_indicitor:
            G_label = 4
    else:
        print('Currently not support graph label with original label {}'.format(label))
        exit

    return G_label

def edges_count(G:nx.Graph, edge:tuple):
    '''
        the edge is directed edge from node[0] to node[1]
    '''
    return G.number_of_edges(edge[0],edge[1])

def token_emb():
    pass

def feature_analysis(df, feature_list:list):
    pass

def visualize_graph(G: nx.Graph, file_path: None):
    # draw the graph
    # print(G.info())
    pos = nx.spring_layout(G)
    # nx.draw_networkx(G, pos)
    nx.draw(G, pos, arrows=True, with_labels=True, node_color='skyblue',font_weight='bold')
    # draw multiple edges
    edge_labels = {(u,v): d['label'] for u, v, d in G.edges(data=True)}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
    plt.show()
    # save the graph
    if file_path:
        nx.write_graphml(G, file_path)
