import re
from bs4 import BeautifulSoup
from requests import get as requests_get


def _translate(versions):
    # First of all let's break the whole string into pieces
    parts = versions.split(',')
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

        if version:
            versions.append(version)
        else:
            print "[!] Could not extract the version for the following string"
            print "\t " + part

    return versions


def get_vulnerabilities():
    base_url = 'https://developer.joomla.org/security-centre.html'
    suffix = ''

    articles = []
    response = requests_get(base_url, verify=False)
    raw = response.text

    articles.extend(BeautifulSoup(raw, 'lxml').select('.blog .items-leading'))
    articles.extend(BeautifulSoup(raw, 'lxml').select('.blog .items-row'))

    for article in articles:
        info = {}
        header = article.select('h2').pop().get_text()
        info['id'] = re.findall('\[(\d{8})\]', header).pop()
        info['title'] = header.split(' - ', 1).pop().strip()
        info['descr'] = article.select('h3 + p')[0].get_text()

        li = article.select('li')

        severity = li[2].get_text()
        severity = severity.split(':').pop().strip()
        info['severity'] = severity.lower()

        # This is the hardest thing, since I have to translate an English phrase into code...
        versions = li[3].get_text()
        versions = versions.split(':').pop().strip()
        info['versions'] = _translate(versions)

        cve = li[7].get_text()
        cve = cve.split(':').pop().strip()

        # For vulnerabilities without a CVE
        if 'CVE' not in cve:
            cve = 'N/A'

        info['cve'] = cve.upper()

if __name__ == '__main__':
    get_vulnerabilities()
