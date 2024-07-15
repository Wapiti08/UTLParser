'''
 # @ Create Time: 2024-07-15 11:27:29
 # @ Modified time: 2024-07-15 14:40:32
 # @ Description: evaluate the processing time for every stage, covering
    log processing, causal graph construction, graph fusion, graph label
 '''
import sys
from pathlib import Path
sys.path.insert(0,Path(sys.path[0]).resolve().parent.as_posix())
from core.logparse.kvparser import KVParser
from core.logparse.genparser import GenLogParser
from core.logparse.reqparser import ReqParser
from core.graph_create.unstrcgraph import UnstrGausalGraph
from core.graph_create.gfusion import GraphFusion
from core.graph_label import graphlabel
import time
import config
import logging
import networkx as nx

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
logger = logging.getLogger(__name__)
file_handler = logging.FileHandler('app.log')
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

format_dict = {
    "DNS": {
        "dnsmasq": {
            "log_format": "<Month> <Date> <Timestamp> <Component>: <Content>",
            # match the domain, ipv4 and ipv6
            "regex": [config.regex['domain'], config.regex['ip4'], config.regex['ip6']],
            "st":0.3,
            # right
            'depth':4,
        },
    },
}

cur_path = Path.cwd()
indir = cur_path.joinpath("large_data").as_posix()
outdir = cur_path.joinpath("large_data","result").as_posix()

graphfusion = GraphFusion(config.avg_len, cur_path.parent.joinpath("core","entity_reco"))


def eval_genlog_parse():
    logger.info("evaluting general logs")
    # --------------- log parsing ---------------
    now = time.time()

    rex = format_dict['DNS']['dnsmasq']['regex']
    log_format = format_dict['DNS']['dnsmasq']['log_format']
    depth = format_dict['DNS']['dnsmasq']['depth']
    st = format_dict['DNS']['dnsmasq']['st']

    logparser = GenLogParser(
        depth=depth,
        st=st,
        rex = rex,
        indir=indir,
        outdir=outdir,
        log_format=log_format,
        log_name="dns.log",
        keep_para=True,
        maxChild=100,
    )

    logparser.load_data()
    logparser.parse()
    logparser.poi_ext()
    logparser.get_output(0)

    logger.info("Time spent for general log parsing is: {}".format(time.time() - now))

    # --------------- causal graph ---------------
    now = time.time()
    dns_unstrgraph = UnstrGausalGraph(outdir, "dns")
    dns_unstrgraph.data_load()
    dns_unstrgraph.causal_graph()
    logger.info("Time spent for dns causal graph is: {}".format(time.time() - now))


def eval_kvlog_parse():
    logger.info("evaluting key-value logs")

    # --------------- log parsing ---------------
    now = time.time()

    # test for apache audit
    logparser = KVParser(
        indir=indir,
        outdir=outdir,
        log_name='audit.log',
        log_type='audit',
        app='apache',
    )   
    logparser.log_parse()
    logparser.get_output(0)
    logger.info("Time spent for key-value log parsing is: {}".format(time.time() - now))

    # --------------- causal graph ---------------
    now = time.time()
    audit_unstrgraph = UnstrGausalGraph(outdir, "audit")
    audit_unstrgraph.data_load()
    audit_unstrgraph.causal_graph()
    logger.info("Time spent for audit causal graph is: {}".format(time.time() - now))


def eval_reqlog_parse():
    logger.info("evaluting request logs")

    # --------------- log parsing ---------------
    now = time.time()

    # test for sysdig process
    logparser = ReqParser(
        indir=indir,
        outdir=outdir,
        log_name='access.log',
        log_type='access',
        app='apache',
    )

    logparser.get_output(0)
    logger.info("Time spent for request log parsing is: {}".format(time.time() - now))

    # --------------- causal graph ---------------
    now = time.time()
    access_unstrgraph = UnstrGausalGraph(outdir, "access")
    access_unstrgraph.data_load()
    access_unstrgraph.causal_graph()
    logger.info("Time spent for access causal graph is: {}".format(time.time() - now))


def eval_graph_fusion():

    now = time.time()

    dns_unstrgraph = UnstrGausalGraph(outdir, "dns")
    audit_unstrgraph = UnstrGausalGraph(outdir, "audit")
    access_unstrgraph = UnstrGausalGraph(outdir, "access")

    dns_unstrgraph.data_load()
    audit_unstrgraph.data_load()
    access_unstrgraph.data_load()

    graph_list = [
            audit_unstrgraph.causal_graph(),
            dns_unstrgraph.causal_graph(),
            access_unstrgraph.causal_graph()
                ]

    G = graphfusion.graph_conn(graph_list)

    logger.info("Time spent for fusing graph is: {}".format(time.time() - now))

    dns_unstrgraph.graph_save(G, "full")

def eval_graph_label():
    sub_graph = nx.read_graphml(Path(outdir).joinpath("full.graphml"))

    # test for sysdig process
    graphlabeler = graphlabel.GraphLabel(
        attr_iocs_dict=config.attr_iocs_dict,
        label_dict=config.ait_iot_dict,
        )
    now = time.time()
    graphlabeler.subgraph_label(G=sub_graph)[1]
    logger.info("Time spent for labeling graphs is: {}".format(time.time() - now))


if __name__ == "__main__":
    # eval_genlog_parse()
    # eval_kvlog_parse()
    # eval_reqlog_parse()
    # eval_graph_fusion()
    eval_graph_label()

