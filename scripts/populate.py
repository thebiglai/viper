#!/usr/bin/env python
from __future__ import print_function
import os
import sys
import argparse

sys.path.append('/opt/viper')

from datetime import datetime
from datetime import date, timedelta

from viper.core.ui.commands import Commands
from viper.core.project import __project__

"""
Script used to simply import data from a directory structure:
<DATA_HOME>/YYYY/MM/DD/raw/vfiles.

You can use -d to state what date to import, assuming the pathing is the same,

You can use -p to import a while path, if -p is passed, -d is required. It will
create the project as the -d argument.
"""
parser = argparse.ArgumentParser()
parser.add_argument('-d', '--date', dest='date',
                    help='Enter date - YYYYMMDD format. Defaults to yesterday')
parser.add_argument('-p', '--path', dest='path',
                    help='Enter a different default path.')
args = parser.parse_args()

if args.path and not args.date:
    print('Please pass in the -d argument if using the --path arg.')
    print('The project will be created using YYYYmmdd format.')
    sys.exit(1)

# For parsing dates
fmt = '%Y%m%d'

VIPER_HOME = '/opt/viper'
TRIDENT_HOME = '/home/cloudmark/trident_data'
DATE = datetime.strptime(args.date, fmt) if args.date else \
    (date.today() - timedelta(1))
PROJECT = DATE.strftime('%Y%m%d')
DATA_DIR = os.path.join(TRIDENT_HOME, DATE.strftime('%Y'), DATE.strftime('%m'),
                        DATE.strftime('%d'), 'raw/vfiles')
# Just reset DATA_DIR to the user supplied path, if present
DATA_DIR = args.path if args.path else DATA_DIR

if __name__ == '__main__':
    os.chdir(VIPER_HOME)
    # Create a new project from yesterdays date.
    if os.path.isdir(DATA_DIR):
        __project__.open(DATE.strftime('%Y%m%d'))
    else:
        print('{0} does not exist'.format(DATA_DIR))
        sys.exit(1)
    # Initialize the commands object, so we can access cmd_store
    commands = Commands()
    # Doesnt hurt to run against the same day since de-duplication is built in
    commands.cmd_projects('-s' + PROJECT)
    # Store the yesterdays data, dir
    commands.cmd_store('-f' + DATA_DIR)
