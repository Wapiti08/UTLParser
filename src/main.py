import sys
from pathlib import Path
sys.path.insert(0,Path(sys.path[0]).resolve().parent.as_posix())
from utils import util
from core.logparse import unilogparser
import yaml

config = yaml.safe_load("./config.yaml")

class GraphTrace:
    def __init__(self, log_name, config):
        self.log_name = log_name

    def log_parse(self):
        unilogparser(self.log_name, )

    def causal_graph_create(self,):
        pass

if __name__ == "__main__":
    pass