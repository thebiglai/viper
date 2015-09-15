#!/usr/bin/env python
from __future__ import print_function
import os
import sys
import argparse

sys.path.append('/opt/viper')

from datetime import datetime
from datetime import date, timedelta
from viper.core.database import Database
from viper.core.plugins import __modules__
from viper.core.project import __project__
from viper.core.ui.commands import Commands
from modules.eyara import Eyara


FMT = '%Y%m%d'
VIPER_HOME = '/opt/viper'
TRIDENT_HOME = '/home/cloudmark/trident_data'
DATE = (date.today() - timedelta(1))

def populate(args):
    if args.path and not args.date:
        print('Please pass in the -d argument if using the --path arg.')
        print('The project will be created using YYYYmmdd format.')
        sys.exit(1)

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


def eyara(args):
    # __project__.open(project) -> run eyara w db.find(key='all')
    project = PROJECT  # called from global scope
    __project__.open(project)
    module = __modules__['eyara']['obj']()
    module.set_commandline(['scan', '-t', '-a'])
    module.run()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    # Populate subparser
    parser_populate = subparsers.add_parser('populate', help='populate')
    parser_populate.add_argument('-d', '--date', dest='date',
                                 help='Enter date - YYYYMMDD format. Defaults '
                                      'to yesterday')
    parser_populate.add_argument('-p', '--path', dest='path',
                                 help='Enter a different default path.')
    parser_populate.set_defaults(func=populate)
    # Eyara subparser
    parser_eyara = subparsers.add_parser('eyara', help='eyara help')
    parser_eyara.add_argument('-d', '--date', dest='date',
                              help='Date to parser. Defaults to yesterday. '
                                   'Format YYYYMMDD')
    parser_eyara.add_argument('-p', '--path', dest='path')
    parser_eyara.set_defaults(func=eyara)

    args = parser.parse_args()
    # Some vars need to be here as they rely on args
    if args.date:
        DATE = datetime.strptime(args.date, FMT)

    PROJECT = DATE.strftime('%Y%m%d')
    DATA_DIR = os.path.join(TRIDENT_HOME, DATE.strftime('%Y'),
                            DATE.strftime('%m'), DATE.strftime('%d'),
                            'raw/vfiles')
    # Reset DATA_DIR to the user supplied path, if present
    DATA_DIR = args.path if args.path else DATA_DIR
    args.func(args)

