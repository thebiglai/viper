from __future__ import print_function

import subprocess
import os

from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.storage import get_sample_path
from viper.core.session import __sessions__

try:
    import yara

    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False


# TODO: account for individual files
# TODO: print prettier
# TODO: print out matching regex
class Eyara(Module):
    cmd = 'eyara'
    description = 'Yara extended parser'

    def __init__(self):
        super(Eyara, self).__init__()
        subparsers = self.parser.add_subparsers(dest='subname')
        parser_scan = subparsers.add_parser('scan',
            help='Scan files with Yara signatures')
        parser_scan.add_argument('-r', '--rule',
            help='Rule file. Default data/yara/index.yara')
        parser_scan.add_argument('-a', '--all', action='store_true',
            help='Scan all stored files.')

    def rule_index(self):
        """Used to generate a new index.yara each time its called.
        """
        with open('data/yara/index.yara', 'w') as rules_index:
            for rule_file in os.listdir('data/yara'):
                # Skip if the extension is not right, could cause problems.
                if not rule_file.endswith('.yar') \
                        and not rule_file.endswith('.yara'):
                    continue
                # Skip if it's the index itself.
                if rule_file == 'index.yara':
                    continue

                # Add the rule to the index.
                line = 'include "{0}"\n'.format(rule_file)
                rules_index.write(line)

        return 'data/yara/index.yara'

    def scan(self):
        # Generate rule_index if a rule set isn't specifically called
        db = Database()
        samples = []

        rules_file = self.args.rule if self.args.rule else self.rule_index()

        if not os.path.isfile(rules_file):
            self.log('error',
                     'Rule file was not found: {}'.format(self.args.rule))

        if __sessions__.is_set() and not self.args.all:
            samples.append(__sessions__.current.file)
            print(samples)
        else:  # self.args.all is set or no session is open.
            self.log('info', 'Scanning all files.')
            samples = db.find(key='all')

        # Just sending noise to /dev/null
        NULL = open('/dev/null')
        com = '/usr/local/bin/yextend {0} {1}'
        for sample in samples:
            if not sample:
                continue
            sample_path = get_sample_path(sample.sha256)
            if not sample_path:
                continue
            command = com.format(rules_file, sample_path)
            self.log('info',
                     "Scanning {0} ({1})".format(sample.name, sample.sha256))
            try:
                p = subprocess.check_output([command], shell=True, stderr=NULL)
                # TODO: pretty print into prettytables
                self.log('info', p)
            except subprocess.CalledProcessError, e:
                self.log('error', 'Unable to process file: {0}'.format(str(e)))
                continue
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
