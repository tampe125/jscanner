import hashlib
import json
import os


def create_hash():
    prev_version = ''

    try:
        with open('data/hashes.json', 'rb') as json_handle:
            hashes = json.load(json_handle)
    except IOError:
        hashes = {}

    for root, dirs, files in os.walk('import'):
        for filename in files:
            extension = os.path.splitext(filename)[1]

            if extension not in ['.js', '.css']:
                continue

            if ('.min.' in filename) or ('-uncompressed' in filename):
                continue

            parts = root.split('/')
            version = parts[1]
            path = '/'.join(parts[2:]) + '/' + filename

            if version != prev_version:
                print "Analyzing version " + version
                prev_version = version

            with open(root + '/' + filename, 'rb') as handle:
                digest = hashlib.sha1(handle.read()).hexdigest()

                if hashes.get(path, 'foobar') == 'foobar':
                    hashes[path] = {}

                if hashes[path].get(digest, 'foobar') == 'foobar':
                    hashes[path][digest] = []

                if version in hashes[path][digest]:
                    continue

                hashes[path][digest].append(version)

    with open('data/hashes.json', 'wb') as handle:
        json.dump(hashes, handle, indent=2, sort_keys=True)

if __name__ == '__main__':
    create_hash()
