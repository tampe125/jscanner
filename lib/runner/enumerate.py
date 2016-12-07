import json
import re
from collections import OrderedDict
from distutils.version import StrictVersion
from hashlib import sha1 as hashlib_sha1
from requests import get as requests_get
from requests import head as requests_head
from requests import ConnectionError
from lib.runner.abstract import AbstractCommand

__author__ = 'Davide Tampellini'
__copyright__ = '2016 Davide Tampellini - FabbricaBinaria'
__license__ = 'GNU GPL version 3 or later'


class JScannerEnumerate(AbstractCommand):
    def check(self):
        """
        Checks if the remote site is online
        """
        try:
            response = requests_get(self.parentArgs.url, verify=False)
        except ConnectionError:
            raise Exception("[!] Could not connect to the remote site")

        if response.status_code != 200:
            raise Exception("[!] Remote site responded with code: %s" % response.status_code)

    def run(self):
        pass
