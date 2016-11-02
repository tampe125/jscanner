import hashlib
import json
import requests


def get_version():
    base_url = 'http://www.fabbricabinaria.it/'
    version = []

    with open('data/hashes.json', 'rb') as json_handle:
        hashes = json.load(json_handle)

    for filename, signatures in hashes.iteritems():
        response = requests.get(base_url + filename)
        digest = hashlib.sha1(response.text.encode('utf-8')).hexdigest()

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

if __name__ == '__main__':
    get_version()
