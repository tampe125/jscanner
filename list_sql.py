import json
import os
import re


def list_sql():
    prev_version = ''

    try:
        with open('data/sql.json', 'rb') as json_handle:
            sql = json.load(json_handle)
    except IOError:
        sql = {}

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

        sql_versions = set()

        if version != prev_version:
            print "Analyzing version " + version
            prev_version = version

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

    with open('data/sql.json', 'wb') as handle:
        json.dump(sql, handle, indent=2, sort_keys=True)


if __name__ == '__main__':
    list_sql()
