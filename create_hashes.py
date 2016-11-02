import hashlib
import json
import os
import re


def create_hash():
    prev_version = ''
    sign_folders = ['media/media', 'media/system', 'templates']

    try:
        with open('data/hashes.json', 'rb') as json_handle:
            hashes = json.load(json_handle)
    except IOError:
        hashes = {}

    for folder in os.listdir('import'):
        if not os.path.isdir('import/' + folder):
            continue

        # Detect Joomla version
        with open('import/' + folder + '/administrator/manifests/files/joomla.xml', 'rb') as manifest:
            contents = manifest.read()
            version = re.search(r'<version>(?P<version>.*?)</version>', contents).groupdict().get('version', '')

        for sign_folder in sign_folders:
            for root, dirs, files in os.walk('import/' + folder + '/' + sign_folder):
                for filename in files:
                    extension = os.path.splitext(filename)[1]

                    if extension not in ['.js', '.css']:
                        continue

                    if ('.min.' in filename) or ('-uncompressed' in filename):
                        continue

                    parts = root.split('/')
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
