# Data-Driven Security Tool Parser

import json
import re
from collections import defaultdict

class SecurityToolParser:
    def __init__(self, config_file):
        self.config_file = config_file
        self.config_data = self.load_config()
        self.parsed_data = defaultdict(list)
    
    def load_config(self):
        with open(self.config_file, 'r') as f:
            return json.load(f)
    
    def parse_log(self, log_file):
        with open(log_file, 'r') as f:
            for line in f:
                self.parse_line(line)
    
    def parse_line(self, line):
        for pattern, action in self.config_data['patterns'].items():
            if re.search(pattern, line):
                self.parsed_data[action].append(line.strip())
    
    def print_parsed_data(self):
        for action, data in self.parsed_data.items():
            print(f"Action: {action}")
            for item in data:
                print(f"  {item}")

if __name__ == "__main__":
    parser = SecurityToolParser('security_config.json')
    parser.parse_log('system.log')
    parser.print_parsed_data()