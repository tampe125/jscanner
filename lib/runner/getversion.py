import json
from hashlib import sha1 as hashlib_sha1
from requests import get as requests_get
from lib.runner.abstract import AbstractCommand

__author__ = 'Davide Tampellini'
__copyright__ = '2016 Davide Tampellini - FabbricaBinaria'
__license__ = 'GNU GPL version 3 or later'


class JScannerGetversion(AbstractCommand):
    def check(self):
        self.parentArgs.url = self.parentArgs.url.strip('/') + '/'

    def run(self):
        base_url = self.parentArgs.url
        version = []

        with open('data/hashes.json', 'rb') as json_handle:
            hashes = json.load(json_handle)

        for filename, signatures in hashes.iteritems():
            response = requests_get(base_url + filename)
            digest = hashlib_sha1(response.text.encode('utf-8')).hexdigest()

            try:
                candidates = signatures[digest]
            except KeyError:
                continue

            if len(version) == 0:
                version = candidates
            else:
                version = set(version).intersection(candidates)

            if len(version) == 1:
                print "Version found: " + version.pop()
                break

        if len(version) != 1:
            print "Possible versions found: " + ', '.join(version)
