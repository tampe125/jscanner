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


class JScannerGetversion(AbstractCommand):
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
        """
        Tries several techniques to fetch the version of the remote site
        :return:
        """
        print "[*] Analyzing site " + self.parentArgs.url
        print "[*] Trying to get the exact version from the XML file..."
        version = self._xml_file()

        # If we can fetch the XML file, the version is 100% correct
        if not version:
            print "[*] Trying to detect version using SQL installation files..."

            version = self._sql_files()

            # Still no version or more possible candidates? Time to fingerprint the media files
            if len(version) != 1:
                if len(version) > 1:
                    print "\t[*] Found %d version candidates, trying to find the exact one" % len(version)

                print "[*] Trying to detect version using media file fingerprints..."
                version = self._media_files(version)

        print ""
        print "[+] Detected Joomla! versions: %s" % ', '.join(version)

        self._list_vulnerabilities(version)

    def _list_vulnerabilities(self, remote_versions):
        if not remote_versions:
            return

        if len(remote_versions) > 1:
            print ""
            print "[!] Multiple version candidates found, displaying all the possible vulnerabilities."
            print "    PLEASE NOTE: This will likely include false positives"
            print ""

        with open('data/vulnerabilities.json', 'rb') as vuln_handle:
            vulnerabilities = json.load(vuln_handle)

        results = []

        for key, vuln in vulnerabilities.iteritems():
            for versions in vuln['versions']:
                for remote_version in remote_versions:
                    if StrictVersion(versions['min']) <= StrictVersion(remote_version) <= StrictVersion(versions['max']):
                        results.append(vuln)
                        break

        if not results:
            print "[!] No known vulnerabilities found"

        print "[+] Found the following vulnerabilities:"

        for result in results:
            print "\t[%s] - %s" % (result['id'], result['title'])
            print "\t\t" + result['descr']
            print "\t\tSeverity: " + result['severity']
            print "\t\tCVE: " + result['cve']
            print ""

    def _xml_file(self):
        """
        Fastest and easiest way: it will check if the XML manifest file is there
        """
        response = requests_get(self.parentArgs.url.strip('/') + '/administrator/manifests/files/joomla.xml',
                                verify=False)

        if response.status_code != 200:
            return []

        match = re.search(r'<version>(?P<version>.*?)</version>', response.text)

        if not match:
            return []

        version = match.groupdict().get('version', None)

        return [version]

    def _sql_files(self):
        """
        Sometimes the manifest file is removed or missing, let's try to enumerate the possible SQL installation scripts
        and infer the possible version number
        """
        # First of all let's test if we can access the SQL directory
        base_url = self.parentArgs.url.strip('/') + '/administrator/components/com_admin/sql/updates/mysql/'

        try:
            response = requests_head(base_url + '3.0.0.sql', verify=False, allow_redirects=True)
        except ConnectionError:
            return []

        # Bummer, something went wrong or the site is protected by the a WAF
        if response.status_code != 200:
            return []

        # If I'm here, it means that I can do that, now let's try to detect the correct version
        with open('data/sql.json', 'rb') as sql_json:
            sql_versions = json.load(sql_json, object_pairs_hook=OrderedDict)

        # Let's reverse the order so we can test for the most recent ones first
        sql_versions = OrderedDict(sorted(sql_versions.items(), reverse=True))
        detected_file = []
        excluded_versions = []

        # Let's try from the most recent one until the old ones
        for filename, versions in sql_versions.iteritems():
            try:
                response = requests_head(base_url + filename, verify=False, allow_redirects=True)
            except ConnectionError:
                pass

            if response.status_code == 200:
                detected_file = filename
                break
            else:
                excluded_versions.extend(versions)

        if detected_file:
            excluded_versions = set(excluded_versions)
            candidates = sql_versions.get(detected_file, [])
            return list(set(candidates) - excluded_versions)

        return []

    def _media_files(self, version):
        """
        Tries to detect the installed vesion by using the media files fingerprint
        :param version:
        :return:
        """
        base_url = self.parentArgs.url.strip('/') + '/'
        excluded_versions = []

        with open('data/hashes.json', 'rb') as json_handle:
            hashes = json.load(json_handle)

        for filename, signatures in hashes.iteritems():
            response = requests_get(base_url + filename)
            digest = hashlib_sha1(response.text.encode('utf-8')).hexdigest()

            # Missing files? This reveals A LOT about the version!
            if response.status_code == 404:
                for signature, versions in signatures.iteritems():
                    excluded_versions.extend(versions)

                version = list(set(version) - set(excluded_versions))
                continue

            try:
                candidates = signatures[digest]
            except KeyError:
                # This should never happen, but better be safe than sorry
                print "\t[!] Unknown %s signature for file %s" % (digest, filename)
                continue

            if len(version) == 0:
                version = candidates
            else:
                version = set(version).intersection(candidates)

            # We have an exact match, we can stop here
            if len(version) == 1:
                break

        return version
