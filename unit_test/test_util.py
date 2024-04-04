import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import unittest
from utils.util import *
import config


class TestLogparser(unittest.TestCase):

    def test_gen_regex_from_logformat(self):
        test_str = "Jan 15 05:07:26 inet-firewall kernel: [76398.724224] hrtimer: interrupt took 15172948 ns"
        test_str = "Jan 15 06:38:48 inet-firewall dbus-daemon[970]: [system] Reloaded configuration"

        log_format = "<Month> <Day> <Timestamp> <Component> <Level> <Proto>: <Content>"
        headers, regex = gen_regex_from_logformat(log_format)
        print(headers)
        print(regex)

        match = regex.search(test_str.strip())
        message = [match.group(header) for header in headers]
        print(message)

if __name__ == "__main__":
    unittest.main()