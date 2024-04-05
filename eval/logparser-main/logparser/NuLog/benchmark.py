# =========================================================================
# Copyright (C) 2016-2023 LOGPAI (https://github.com/logpai).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# =========================================================================


import sys
sys.path.append("../../")
from pathlib import Path
from logparser.NuLog import LogParser
from logparser.utils import evaluator
import os
import pandas as pd


cur_path = Path.cwd()

input_dir = cur_path.parent.parent.joinpath("data", "loghub").as_posix() 
output_dir = "NuLog_result/"  # The output directory of parsing results


benchmark_settings = {
    "DNS": {
        "log_file": "DNS/dnsmasq.log",
        "log_format": "<Month> <Date> <Timestamp> <Component>: <Content>",
        "filters": "([ ])",
        "k": 50,
        "nr_epochs": 3,
        "num_samples": 0,
    },
    "Apache1":{
        "log_file": "Apache/audit.log",
        "log_format": "<Type> <Time>: <Content>",
        "filters": "([ ])",
        "k": 50,
        "nr_epochs": 3,
        "num_samples": 0,
    },

    "Apache2":{
        "log_file": "Apache/auth.log",
        "log_format": "<Month> <Day> <Timestamp> <Component> <Proto>: <Content>",
        "filters": "([ ])",
        "k": 50,
        "nr_epochs": 3,
        "num_samples": 0,
    },

    "Linux": {
        "log_file": "Linux/syslog.log",
        "log_format": "<Month> <Day> <Timestamp> <Component> <Proto>: <Content>",
        "filters": "([ ])",
        "k": 50,
        "nr_epochs": 3,
        "num_samples": 0,
    }
}

bechmark_result = []
for dataset, setting in benchmark_settings.items():
    print("\n=== Evaluation on %s ===" % dataset)
    indir = os.path.join(input_dir, os.path.dirname(setting["log_file"]))
    log_file = os.path.basename(setting["log_file"])

    parser = LogParser(
        indir=indir,
        outdir=output_dir,
        filters=setting["filters"],
        k=setting["k"],
        log_format=setting["log_format"],
    )
    parser.parse(
        log_file, nr_epochs=setting["nr_epochs"], num_samples=setting["num_samples"]
    )

    F1_measure, accuracy = evaluator.evaluate(
        groundtruth=os.path.join(indir, log_file + "_structured_corr.csv"),
        parsedresult=os.path.join(output_dir, log_file + "_structured.csv"),
    )
    bechmark_result.append([dataset, F1_measure, accuracy])


print("\n=== Overall evaluation results ===")
df_result = pd.DataFrame(bechmark_result, columns=["Dataset", "F1_measure", "Accuracy"])
df_result.set_index("Dataset", inplace=True)
print(df_result)
df_result.to_csv("NuLog_bechmark_result.csv", float_format="%.6f")
