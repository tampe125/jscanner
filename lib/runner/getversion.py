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
        version = self._xml_file()

        # If we can fetch the XML file, the version is 100% correct
        if version:
            return version

        version = self._sql_files()

        # If we have an exact match, let's return it
        if len(version) == 1:
            return version

        # Still no version or more possible candidates? Time to fingerprint the media files
        version = self._media_files(version)

        return version
    
    def _xml_file(self):
        return []

    def _sql_files(self):
        return []

    def _media_files(self, version):
        base_url = self.parentArgs.url

        with open('data/hashes.json', 'rb') as json_handle:
            hashes = json.load(json_handle)

        for filename, signatures in hashes.iteritems():
            response = requests_get(base_url + filename)
            digest = hashlib_sha1(response.text.encode('utf-8')).hexdigest()

            try:
                candidates = signatures[digest]
            except KeyError:
                # This should never happen, but better be safe than sorry
                # TODO Warning style
                print "Unknown %s signature for file %s" % (digest, filename)
                continue

            if len(version) == 0:
                version = candidates
            else:
                version = set(version).intersection(candidates)

            # We have an exact match, we can stop here
            if len(version) == 1:
                break

        return version
