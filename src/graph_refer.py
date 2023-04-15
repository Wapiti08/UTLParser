'''
 * @Author: Newt Tan 
 * @Date: 2023-04-15 16:15:30 
 * @Last Modified by:   Newt Tan 
 * @Last Modified time: 2023-04-15 16:15:30 

'''
import asyncio
import dask.dataframe as dd
import dask
import ray
import networkx as nx
import tqdm

def web_req_graph(req_url_list: list, ref_url_list:list, undir=False):
    ''' build the web request graph based on requested url and referer values
    referer value points at previous accessed url 
    '''
    edge_list = []
    # in order to do the refactoring for graph
    ord_list = []
    i = 0
    for ref_url, req_url in tqdm(zip(ref_url_list, req_url_list), desc="traversing refer values in http requests"):
        if ref_url is not None:
            edge_list.append((ref_url, req_url))
            ord_list.append(i)
        i += 1

    G = nx.MultiDiGraph()
    G.add_edges_from(edge_list)

    return G, ord_list

def redirect_reconstruct_status_code(order_list: list, dd: dask.dataframe):
    ''' reconstruct redirected url for missing user initial request (single graph)

    '''
    # check the response code (301, 302, 303, 307)
    redirect_resp_code = [301, 302, 303, 307]

def redirect_reconstruct_html(order_list: list, dd: dask.dataframe):
    ''' apply on single graph based on html element for redirection check

    '''


def redirect_reconstruct_js(order_list: list, dd: dask.dataframe):
    ''' apply on single graph based on js element for redirection check
    
    '''
    

def url_similarity_score():
    ''' calculat the similarity score of two urls

    a = y(A, B) / max(b(A),b(B))
    y(A,B) is the number if elements in common
    max(b(A), b(B)) is the maxmium of elements

    '''
    pass


def outlier_filter():
    ''' implement Local Oultier Filter(LOF) to filter out normal traffic
    
    '''
    pass
