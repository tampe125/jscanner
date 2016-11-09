import argparse
import logging
import re
import requests.packages.urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning, InsecurePlatformWarning
from textwrap import dedent as textwrap_dedent

__author__ = 'Davide Tampellini'
__copyright__ = '2015 Davide Tampellini - FabbricaBinaria'
__license__ = 'GNU GPL version 3 or later'


class JScanner:
    def __init__(self):

        # Disable warnings about SSL connections
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)

        self.settings = None
        self.version = '1.0.0'

        parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                         description=textwrap_dedent('''
JScanner - What's under the hood?
 This is the main entry point of JScanner, where you can perform all the actions.
 Type:
    jscanner [command] [options]
 to run a specific command

 Type:
    jscanner [command] -h
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
        print("JScanner " + self.version + " - What's under the hood?")
        print("Copyright (C) 2016 FabbricaBinaria - Davide Tampellini")
        print("===============================================================================")
        print("JScanner is Free Software, distributed under the terms of the GNU General")
        print("Public License version 3 or, at your option, any later version.")
        print("This program comes with ABSOLUTELY NO WARRANTY as per sections 15 & 16 of the")
        print("license. See http://www.gnu.org/licenses/gpl-3.0.html for details.")
        print("===============================================================================")

    def checkenv(self):
        pass

    def check_updates(self):
        pass

    def run(self):
        self.banner()
        self.check_updates()

        # Perform some sanity checks
        try:
            self.checkenv()
        except Exception as error:
            print "[!] " + str(error)
            return

        # Let's load the correct object
        if self.args.command == 'analyze':
            from lib.runner import analyze
            runner = analyze.JScannerAnalyze(self.args)
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
