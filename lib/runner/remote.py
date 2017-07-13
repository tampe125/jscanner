from abc import ABCMeta
from requests import ConnectionError
from requests import get as requests_get
from abstract import AbstractCommand

__author__ = 'Davide Tampellini'
__copyright__ = '2016-2017 Davide Tampellini - FabbricaBinaria'
__license__ = 'GNU GPL version 3 or later'


class RemoteCommand(AbstractCommand):
    __metaclass__ = ABCMeta

    def check(self):
        """
        Checks if the remote site is online
        """
        if not self.parentArgs.quiet:
            print "[*] Checking if URL %s is online" % self.parentArgs.url

        try:
            response = requests_get(self.parentArgs.url, verify=False)
        except ConnectionError:
            raise Exception("[!] Could not connect to the remote site")

        if response.status_code != 200:
            raise Exception("[!] Remote site responded with code: %s" % response.status_code)

        if not self.parentArgs.quiet:
            print "[+] Site %s seems online" % self.parentArgs.url
