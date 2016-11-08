import json
import os
import re
import shutil
import zipfile
from lib.runner.abstract import AbstractCommand
from hashlib import sha1 as hashlib_sha1


class JScannerGethashes(AbstractCommand):
    def check(self):
        return True

    def run(self):
        prev_version = ''

        try:
            with open('data/hashes.json', 'rb') as json_handle:
                hashes = json.load(json_handle)
        except IOError:
            hashes = {}

        try:
            with open('data/sql.json', 'rb') as json_handle:
                sql = json.load(json_handle)
        except IOError:
            sql = {}

        # First of all let's see if we have to unpack any zip files:
        for filename in os.listdir('import'):
            file_path = 'import/' + filename
            if not os.path.isfile(file_path):
                continue

            # Process only ZIP files
            basename, extension = os.path.splitext(file_path)
            basename = os.path.basename(basename)
            target_dir = 'import/' + basename

            if extension != '.zip':
                continue

            if os.path.isdir(target_dir):
                shutil.rmtree(target_dir)

            if not os.path.isdir(target_dir):
                os.makedirs(target_dir)

            zip_ref = zipfile.ZipFile(file_path, 'r')
            zip_ref.extractall(target_dir)
            zip_ref.close()

        for folder in os.listdir('import'):
            if not os.path.isdir('import/' + folder):
                continue

            # Detect Joomla version
            try:
                with open('import/' + folder + '/administrator/manifests/files/joomla.xml', 'rb') as manifest:
                    contents = manifest.read()
                    version = re.search(r'<version>(?P<version>.*?)</version>', contents).groupdict().get('version', '')
            except IOError:
                version = ''

            if not version:
                print "Could not detect Joomla! version for folder: " + folder
                continue

            if version != prev_version:
                print "Analyzing version " + version
                prev_version = version

            self._media_hashes(version, folder, hashes)
            self._list_sql(version, folder, sql)

        with open('data/hashes.json', 'wb') as handle:
            json.dump(hashes, handle, indent=2, sort_keys=True)

        with open('data/sql.json', 'wb') as handle:
            json.dump(sql, handle, indent=2, sort_keys=True)

    def _media_hashes(self, version, folder, hashes):
        sign_folders = ['media/media', 'media/system', 'templates']

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

                    with open(root + '/' + filename, 'rb') as handle:
                        digest = hashlib_sha1(handle.read()).hexdigest()

                        if hashes.get(path, 'foobar') == 'foobar':
                            hashes[path] = {}

                        if hashes[path].get(digest, 'foobar') == 'foobar':
                            hashes[path][digest] = []

                        if version in hashes[path][digest]:
                            continue

                        hashes[path][digest].append(version)

    def _list_sql(self, version, folder, sql):
        sql_versions = set()

        for filename in os.listdir('import/' + folder + '/administrator/components/com_admin/sql/updates/mysql'):
            extension = os.path.splitext(filename)[1]

            if extension not in ['.sql']:
                continue

            if filename.startswith('2.5'):
                continue

            file_version = re.search(r'(?P<version>\d\.\d\.\d).*?\.sql', filename).groupdict().get('version', '')

            if file_version in sql_versions:
                continue

            sql_versions.add(file_version)

            if sql.get(filename, 'foobar') == 'foobar':
                sql[filename] = []

            if version in sql[filename]:
                continue

            sql[filename].append(version)
