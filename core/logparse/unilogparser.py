import sys
from pathlib import Path
sys.path.insert(0,Path(sys.path[0]).resolve().parent.as_posix())
from utils import util
from core.logparse import kvparser
from core.logparse import reqparser
from core.logparse import genparser
from core.logparse import uniformat
from core.logparse import strreader
import config
import logging
import ray

# set the configuration
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )

# create a logger
logger = logging.getLogger(__name__)

class LogParser:
    def __init__(self, log_app, log_path, output_path, iocs_list):
        '''
        :param log_path: the full path of log file
        :param output_path: parent folder to save result
        :param iocs_list: desired entity types to extract from log context --- for genparser
        '''
        self.log_app = log_app
        self.log_path = log_path
        self.output_path = output_path
        self.iocs_list = iocs_list

    def choose_logparser(self,):
        indir = Path(self.log_path).parent
        outdir = self.output_path
        logname = Path(self.log_path).stem
        
        if logname in config.log_type["kv"]:
            logparser = kvparser.KVParser(
                indir = indir,
                outdir = outdir,
                log_name= Path(self.log_path).name,
                log_type = logname,
                app = self.log_app
                )
            
        elif logname in config.log_type["req"]:
            logparser = reqparser.ReqParser(
                indir = indir,
                outdir = outdir,
                log_name= Path(self.log_path).name,
                log_type = logname,
                app = self.log_app
            )
        
        elif logname in config.log_type["gen"]:
            # check whether parameters have been calculated before
            if self.log_app in config.format_dict.keys():
                if logname in config.format_dict[self.log_app].keys():
                    # rex is decided by types of IOCs to extract
                    rex = config.format_dict[self.log_app]["regex"]
                    log_format = config.format_dict[self.log_app]["log_format"]
                    depth = config.format_dict[self.log_app]["depth"]
                    st = config.format_dict[self.log_app]["st"]
                else:
                    logger.info("{} in {} has not been processed before, \
                                generating parameters".format(logname, self.log_app))
                    # check whether desired entities have been provided
                    if not self.iocs_list:
                        logger.warn("The desired entities have not been provided, please add a list in command")
                        sys.exit(1)
                    else:
                        rex = [config.regex[ioc] for ioc in self.iocs_list ]
                    depth, thres, log_format = self.gen_parser_paras()
            else:
                logger.info("logs in {} has not been processed before, \
                            generating parameters".format(logname, self.log_app))
                # check whether desired entities have been provided
                if not self.iocs_list:
                    logger.warn("The desired entities have not been provided, please add a list in command")
                    sys.exit(1)
                else:
                    rex = [config.regex[ioc] for ioc in self.iocs_list ]
                depth, thres, log_format = self.gen_parser_paras()
            
            # parse general logs
            logparser = genparser.GenLogParser(
                depth=depth,
                st=thres,
                rex = rex,
                indir=indir,
                outdir=outdir,
                log_format=log_format,
                log_name = Path(self.log_path).name,
                keep_para=True,
                maxChild=100,
                )

        elif logname in config.log_type["str"]:
            logparser = strreader.StrLogParser(
                indir = indir,
                outdir = outdir,
                log_name= Path(self.log_path).name,
                log_type = logname,
                app = self.log_app
            )
        return logparser

    def gen_parser_paras(self,):
        # calculate parameter
        uniformer = uniformat.UniFormat(Path(self.log_path))
        sens = uniformer.ran_pick(10)
        depth = uniformer.cal_depth(sens)
        thres = uniformer.cal_thres(sens)
        log_format_dict = {}
        log_format_list = []
        for _, sen in enumerate(sens):
            log_format_dict_res = uniformer.com_check(sen, 0, ":", 1, log_format_dict)
            if log_format_dict_res:
                log_format_list.append(uniformer.com_rule_check(log_format_dict_res))
        
        log_format_dict = uniformer.final_format(log_format_list)
        log_format = uniformer.format_ext(log_format_dict)
        return depth, thres, log_format

    def generate_output(self, logparser):
        logparser.parse()
        logparser.poi_ext()
        logparser.get_output(0)