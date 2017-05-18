import json
import re
from bs4 import BeautifulSoup
from requests import get as requests_get
from lib.runner.abstract import AbstractCommand

__author__ = 'Davide Tampellini'
__copyright__ = '2016-2017 Davide Tampellini - FabbricaBinaria'
__license__ = 'GNU GPL version 3 or later'


class JScannerGetvuln(AbstractCommand):
    def check(self):
        return True

    def run(self):
        base_url = 'https://developer.joomla.org'
        target_url = '/security-centre.html'
        more = True
        vulnerabilities = {}

        while more:
            articles = []
            response = requests_get(base_url + target_url, verify=False)
            soup = BeautifulSoup(response.text, 'lxml')

            articles.extend(soup.select('.blog .items-leading'))
            articles.extend(soup.select('.blog .items-row'))

            for article in articles:
                info = {}
                header = article.select('h2[itemprop=name]').pop().get_text()
                info['id'] = re.findall('\[(\d{8})\]', header)[0]
                info['title'] = header.split(' - ', 1).pop().strip()
                descr_header = article(text=re.compile(r'Description')).pop().parent
                info['descr'] = descr_header.find_next('p').get_text()

                li = article.select('li')

                # In some cases we could not have the severity
                try:
                    severity = li[2].get_text()
                    severity = severity.split(':').pop().strip()
                except IndexError:
                    severity = 'n/a'

                info['severity'] = severity.lower()

                # This is the hardest thing, since I have to translate an English phrase into code...
                try:
                    versions = li[3].get_text()
                    versions = versions.split(':').pop().strip()
                    info['versions'] = self._translate(versions)
                except IndexError:
                    info['versions'] = []

                # Sometimes the CVE info is not there
                try:
                    cve = li[7].get_text()
                    cve = cve.split(':').pop().strip()

                    # For vulnerabilities without a CVE
                    if 'CVE' not in cve:
                        cve = 'N/A'
                except IndexError:
                    cve = 'N/A'

                info['cve'] = cve.upper()
                vulnerabilities[info['id']] = info

            pagination = soup.select('ul.pagination-list li a[title=Next]')
            with open('data/vulnerabilities.json', 'wb') as json_file:
                json.dump(vulnerabilities, json_file, sort_keys=True, indent=2)

            if not pagination:
                more = False
            else:
                target_url = pagination.pop().get('href')

    def _translate(self, versions):
        # First of all let's break the whole string into pieces
        # On previous security bulletin we have messages like this: ... and earlier 2.5x versions. 3.0.x ...
        legacy = re.split('versions\.\s', versions)
        parts = []

        for item in legacy:
            parts.extend(re.split(',|;', item))

        versions = []

        for part in parts:
            part = part.strip()
            # Replace non breaking spaces with real spaces
            part = part.replace(u'\xa0', u' ')
            version = {}

            # Single version
            if not version:
                match = re.search('^(\d\.\d.\d{1,2})$', part)
                if match:
                    version['min'] = match.group(1)
                    version['max'] = match.group(1)

            # Easy one: 3.3.3 through 3.4.0
            if not version:
                match = re.search('(\d\.\d.\d{1,2})\s+through\s+(\d\.\d.\d{1,2})', part)
                if match:
                    version['min'] = match.group(1)
                    version['max'] = match.group(2)

            # 3.2.5 and earlier 3.x versions |  2.5.24 and (all) earlier 2.5.x versions
            if not version:
                match = re.search(
                    '(\d\.\d.\d{1,2}) and (?:all )?(?:earlier|previous) (1\.5|1\.5\.x|1\.6\.x|2\.5\.x|3\.x|3\.0\.x)',
                    part)
                if match:
                    if match.group(2).startswith('1.5'):
                        min_vers = '1.5.0'
                    elif match.group(2).startswith('2.5'):
                        min_vers = '2.5.0'
                    else:
                        min_vers = '3.0.0'
                    version['min'] = min_vers
                    version['max'] = match.group(1)

            if version:
                versions.append(version)
            else:
                print "[!] Could not extract the version for the following string"
                print "\t " + part

        return versions
