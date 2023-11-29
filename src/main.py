import sys
from pathlib import Path
sys.path.insert(0,Path(sys.path[0]).resolve().parent.as_posix())
from utils import util


if __name__ == "__main__":
    root_path = Path(sys.path[0]).resolve()
    log_file = root_path.joinpath('data\IoT\iot_23_datasets\iot_23_datasets_small\IoTScenarios',\
                                  'CTU-IoT-Malware-Capture-35-1\\bro\conn.log.labeled').as_posix()
    graph_list = util.graph_from_structure_data(log_file)
    util.visualize_graph(graph_list[0])