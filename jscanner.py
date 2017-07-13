import argparse
import logging
import re

from textwrap import dedent as textwrap_dedent
from datetime import datetime

__author__ = 'Davide Tampellini'
__copyright__ = '2016-2017 Davide Tampellini - FabbricaBinaria'
__license__ = 'GNU GPL version 3 or later'


class JScanner:
    def __init__(self):
        self.settings = None
        self.version = '1.3.0'

        parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                         description=textwrap_dedent('''
JScanner - What's under the hood?
 This is the main entry point of JScanner, where you can perform all the actions.
 Type:
    jscanner.py [command] [options]
 to run a specific command

 Type:
    jscanner.py [command] -h
 to display the help for the specific command
        '''))

        subparsers = parser.add_subparsers(dest='command')

        analyze_descr = "Analyze target Joomla! installation"
        parser_analyze = subparsers.add_parser('analyze', help=analyze_descr, description=analyze_descr)
        parser_analyze.add_argument('-u', '--url',
                                    help='URL of the remote site',
                                    required=True)
        parser_analyze.add_argument('-t', '--technique',
                                    help="Force technique to retrieve the remote version",
                                    required=False,
                                    choices=['all', 'xml', 'sql', 'media'],
                                    default="all")
        parser_analyze.add_argument('-q', '--quiet',
                                    help="Quiet mode",
                                    required=False,
                                    default=False,
                                    action='store_true')

        enumerate_descr = "Enumerates registered usernames or emails"
        parser_enumerate = subparsers.add_parser('enumerate', help=enumerate_descr, description=enumerate_descr)
        parser_enumerate.add_argument('-u', '--url',
                                      help='URL of the remote site',
                                      required=True)

        enumerate_group = parser_enumerate.add_mutually_exclusive_group(required=True)
        enumerate_group.add_argument('-U', '--users',
                                     help='File containing the list of users to test',
                                     type=argparse.FileType('r'))

        enumerate_group.add_argument('-e', '--emails',
                                     help='File containing the list of emails to test',
                                     type=argparse.FileType('r'))

        get_vuln_descr = "Fetches the list of all vulnerabilities from Joomla! official site"
        subparsers.add_parser('getvuln', help=get_vuln_descr, description=get_vuln_descr)

        get_hash_descr = "Calculates the hash signature for media files and compiles the list of SQL files"
        subparsers.add_parser('gethashes', help=get_hash_descr, description=get_hash_descr)

        self.args = parser.parse_args()

        # If the url has no protocol I'll add it
        try:
            if re.search(r'http(s?)://', self.args.url) is None:
                self.args.url = 'http://' + self.args.url
        except AttributeError:
            pass

        # Let's silence the requests package logger
        logging.getLogger("requests").setLevel(logging.WARNING)

    def banner(self):
        now = datetime.now()

        print("JScanner " + self.version + " - What's under the hood?")
        print("Copyright (C) 2016-" + str(now.year) + " FabbricaBinaria - Davide Tampellini")
        print("===============================================================================")
        print("JScanner is Free Software, distributed under the terms of the GNU General")
        print("Public License version 3 or, at your option, any later version.")
        print("This program comes with ABSOLUTELY NO WARRANTY as per sections 15 & 16 of the")
        print("license. See http://www.gnu.org/licenses/gpl-3.0.html for details.")
        print("===============================================================================")

    def checkenv(self):
        try:
            import requests.packages.urllib3
        except ImportError:
            raise Exception('requests package not installed. Run pip install -r requirements.txt and try again.')

        # Disable warnings about SSL connections
        try:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        except ImportError:
            pass

        try:
            from requests.packages.urllib3.exceptions import InsecurePlatformWarning
            requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
        except ImportError:
            pass

    def check_updates(self):
        pass

    def run(self):
        if not self.args.quiet:
            self.banner()

        # Perform some sanity checks
        try:
            self.checkenv()
        except Exception as error:
            print "[!] " + str(error)
            return

        self.check_updates()

        # Let's load the correct object
        if self.args.command == 'analyze':
            from lib.runner import analyze
            runner = analyze.JScannerAnalyze(self.args)
        elif self.args.command == 'enumerate':
            from lib.runner import enumerate
            runner = enumerate.JScannerEnumerate(self.args)
        elif self.args.command == 'getvuln':
            from lib.runner import getvuln
            runner = getvuln.JScannerGetvuln(self.args)
        elif self.args.command == 'gethashes':
            from lib.runner import gethashes
            runner = gethashes.JScannerGethashes(self.args)
        else:
            print ("[!] Unrecognized command " + self.args.command)
            return

        # And away we go!
        try:
            runner.check()
            runner.run()
        # Ehm.. something wrong happened?
        except Exception as error:
            print "[!] " + str(error)

try:
    scraper = JScanner()
    scraper.run()
except KeyboardInterrupt:
    print("")
    print ("[*] Operation aborted")
