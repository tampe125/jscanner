import json
import re
from hashlib import sha1 as hashlib_sha1
from requests import get as requests_get
from requests import ConnectionError
from lib.runner.abstract import AbstractCommand

__author__ = 'Davide Tampellini'
__copyright__ = '2016 Davide Tampellini - FabbricaBinaria'
__license__ = 'GNU GPL version 3 or later'


class JScannerGetversion(AbstractCommand):
    def check(self):
        # Check if the remote site is online
        try:
            response = requests_get(self.parentArgs.url, verify=False)
        except ConnectionError:
            raise Exception("Could not connect to the remote site")

        if response.status_code != 200:
            raise Exception("Remote site responded with code: %s" % response.status_code)

    def run(self):
        # TODO Info stying
        print "Trying to get the exact version from the XML file..."
        version = self._xml_file()

        # If we can fetch the XML file, the version is 100% correct
        if version:
            return version

        print "Trying to detect version using SQL installation files..."

        version = self._sql_files()

        # If we have an exact match, let's return it
        if len(version) == 1:
            return version

        if len(version) > 1:
            print "Found %d version candidates, trying to find the exact one" % len(version)

        print "Trying to detect version using media file fingerprints..."

        # Still no version or more possible candidates? Time to fingerprint the media files
        version = self._media_files(version)

        return version

    def _xml_file(self):
        response = requests_get(self.parentArgs.url.strip('/') + '/administrator/manifests/files/joomla.xml', verify=False)

        if response.status_code != 200:
            return None

        match = re.search(r'<version>(?P<version>.*?)</version>', response.text)

        if not match:
            return None

        version = match.groupdict().get('version', None)

        return version

    def _sql_files(self):
        return []

    def _media_files(self, version):
        base_url = self.parentArgs.url.strip('/') + '/'

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
