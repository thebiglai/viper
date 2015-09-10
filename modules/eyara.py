from __future__ import print_function

import subprocess
import json

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.storage import get_sample_path
from viper.core.session import __sessions__

try:
    import yara

    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False


# TODO: need to add in the ability to tag
# TODO: return json, api will return json with padding.
class Eyara(Module):
    cmd = 'eyara'
    description = 'Yara extended parser'

    def __init__(self, json_out=True):
        super(Eyara, self).__init__()
        subparsers = self.parser.add_subparsers(dest='subname')
        parser_scan = subparsers.add_parser('scan', help='Scan files with Yara '
                                                         'signatures')
        parser_scan.add_argument('-r', '--rule',
                                 help='Rule file. Default data/yara/index.yara')
        parser_scan.add_argument('-a', '--all', action='store_true',
                                 help='Scan all stored files.')
        self.json_out = json_out
        self.jout = {'data': []}

    def rule_index(self):
        """Used to generate a new index.yara each time its called.
        """
        with open('data/yara/index.yara', 'w') as rules_index:
            for rule_file in os.listdir('data/yara'):
                # Skip if the extension is not right, could cause problems.
                if not rule_file.endswith('.yar') and not rule_file.endswith(
                        '.yara'):
                    continue
                # Skip if it's the index itself.
                if rule_file == 'index.yara':
                    continue

                # Add the rule to the index.
                line = 'include "{0}"\n'.format(rule_file)
                rules_index.write(line)

        return 'data/yara/index.yara'

    def scan(self):
        # Parse subprocess's output here
        def output_parser(out):
            # The list of lists we return to the calling process
            rows = []
            # Temp store for lists
            row = []
            # break stdout up into a list so we can iterate
            parse = [x for x in out.split('\n') if x != '']
            for line in parse:
                if line == '' or line == '\n':
                    continue
                key, val = line.split(':', 1)
                if key == 'Parent File Name':
                    continue
                elif key == 'File Signature (MD5)':
                    row.append(val)
                    rows.append(row)
                    row = []
                else:
                    row.append(val)
            return rows

        def generate_json(out):
            # TODO: group by parent file
            j = {}
            parse = [x for x in out.split('\n') if x != '']
            for line in parse:
                if line == '' or line == '\n':
                    continue
                key, val = line.split(':', 1)
                if key == 'Yara':
                    if ',' in val:
                        val = [x.strip() for x in val.split(',')]
                    else:
                        val = [val.strip()]
                    j[key] = val
                elif key == 'File Signature (MD5)':
                    j[key] = val.strip()
                    self.jout['data'].append(j)
                    j = {}
                else:
                    j[key] = val.strip()

        db = Database()
        samples = []
        header = ['Rule', 'Type', 'File', 'Md5']
        com = '/usr/local/bin/yextend {0} {1}'
        rules_file = self.args.rule if self.args.rule else self.rule_index()

        if not os.path.isfile(rules_file):
            print_error('Rule file was not found: {}'.format(self.args.rule))

        if __sessions__.is_set() and not self.args.all:
            samples.append(__sessions__.current.file)
        else:
            print_info('Scanning all files, this might take a bit')
            samples = db.find(key='all')

        # sending noise to /dev/null
        NULL = open('/dev/null')
        # Main loop for scanning here
        for sample in samples:
            if not sample:
                continue

            sample_path = get_sample_path(sample.sha256)
            if not sample_path:
                continue

            print_info("Scanning {0} ({1})".format(sample.name, sample.sha256))
            command = com.format(rules_file, sample_path)
            try:
                p = subprocess.check_output([command], shell=True, stderr=NULL)
            except subprocess.CalledProcessError, e:
                print_error('Unable to process file: {0}'.format(str(e)))
                continue

            if self.json_out:
                output = generate_json(p)
            else:
                rows = output_parser(p)
                if rows:
                    print(table(header=header, rows=rows))

        if self.json_out:
            print(json.dumps(self.jout))

        # Don't forget to close this guy out
        NULL.close()

    def run(self):
        super(Eyara, self).run()
        if self.args is None:
            return

        if not os.path.exists('/usr/local/bin/yextend'):
            self.log('error', 'Missing dependency yextend. See \
                              https://github.com/BayshoreNetworks/yextend')
            return

        if not HAVE_YARA:
            self.log('error', "Missing dependency, install yara")
            return

        if self.args.subname == 'scan':
            self.scan()
        else:
            self.log('error', 'At least one of the parameters is required')
            self.usage()
