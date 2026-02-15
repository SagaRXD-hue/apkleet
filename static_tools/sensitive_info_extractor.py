import os
import re
from .utility.utility_class import util

"""
    Title:      APKDeepLens
    Desc:       Android security insights in full spectrum.
    Author:     Deepanshu Gajbhiye
    Version:    1.0.0
    GitHub URL: https://github.com/d78ui98/APKDeepLens
"""
SEVERITY_MAP = {
    "google_api": ("Critical", "M9", "Remove from source, use env vars"),
    "amazon_aws_access_key_id": ("Critical", "M9", "Rotate immediately"),
    "private_ssh_key": ("Critical", "M9", "Revoke key"),
    "generic_secret": ("High", "M9", "Move to secure storage"),
    "ip_address": ("Medium", "M3", "Verify endpoint security"),
}



class bcolors:
    HEADER = ''
    OKBLUE = ''
    OKCYAN = ''
    OKGREEN = ''
    WARNING = ''
    FAIL = ''
    ENDC = ''
    BOLD = ''
    UNDERLINE = ''



class SensitiveInfoExtractor(object):

    def get_all_file_paths(self, file_path):
        totalFiles = []
        for root, dirs, files in os.walk(file_path):
            tempFiles = [os.path.join(file_path,os.path.join(root, i)) for i in files]
            totalFiles += tempFiles

        return totalFiles 
    
    def extract_all_sensitive_info(self, list_of_files, relative_path):
        """
        This function detects M1: Insecure Authentication/Authorization
        Extracts all the keys for all the apk file
        in: file list - all file path
            relative - gives the path relative to this path
        Out: string path: key type: value
        """
        all_sensitive_info_list = []
        indent = "    "

        excluded_extensions = ['.ttf', '.otf', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.dex', '.gradle']

        try:
            for file in list_of_files:
                _, file_extension = os.path.splitext(file)
                if file_extension.lower() not in excluded_extensions:
                    read = open(file, "r", encoding='utf-8', errors='ignore').read() 
                    types_ioc_list = self.extract(read) 
                    #fetching relative path
                    real_relative_path = os.path.relpath(file, relative_path)
                    for items in types_ioc_list:
                        print(indent + items)
                        ioc_and_type = items.split()
                        ####
                        stype = ioc_and_type[0]

                        severity, owasp, fix = self.SEVERITY_MAP.get(
                            stype,
                            ("Low", "M9", "Review manually")
                        )

                        secret_info = {
                            "title": "Hardcoded Secret",
                            "severity": "High",
                            "confidence": "High",
                            "owasp": "M2: Insecure Data Storage",
                            "path": real_relative_path,
                            "description": f"Hardcoded sensitive value: {ioc_and_type[0]}",
                            "remediation": "Store secrets securely using Android Keystore"
                        }


                        ####
                        all_sensitive_info_list.append(secret_info)
                        items = "{}: {}".format(real_relative_path, items)
            return all_sensitive_info_list
        except Exception as e:
            return str(e) 
    
    def extract_insecure_request_protocol(self, list_of_files):
        """
        This function detects M2: Insecure Communication in OWASP Top 10
        It will check for all the insure communication used throughout the app source code.
        """
        final_list = list()
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_dir, 'known_false_positives.txt')
        # Read known false positives from a file
        with open(file_path, 'r') as f:
            known_false_positives = [line.strip() for line in f]
        for file in list_of_files:
            try:
                read = open(file, "r", encoding='utf-8', errors='ignore').read()
                regex_for_insecure_conn = "((?:http://|s?ftp://|smtp://|:javascript:|www\d{0,3}[.])[\w().=/;,#:@?&~*+!$%\{}-]+)"
                a = re.findall(regex_for_insecure_conn, read)
                for i in a:
                    # Only add to the list if it is not a known false positive
                    if not any(re.match(fp, i) for fp in known_false_positives):
                        final_list.append(i)
            except Exception as e:
                return str(e)
        return list(set(final_list))
    def is_real_public_ip(self, ip):

        blocked = [
            "0.", "10.", "127.", "192.168.",
            "169.254.",
            "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31."
        ]

        for p in blocked:
            if ip.startswith(p):
                return False

        return True

    
    def extract(self, text):
        """
        This function is used to scan the given text for predefined patterns of sensitive information.
        Detected potential security issues in "{pattern_name}: {match}" format.
        """
        patterns = {
            "slack_token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
            "slack_webhook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
            "facebook_oauth": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]",
            "twitter_oauth": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]",
            "twitter_access_token": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
            "heroku_api": "[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
            "mailgun_api": "key-[0-9a-zA-Z]{32}",
            "mailchamp_api": "[0-9a-f]{32}-us[0-9]{1,2}",
            "picatic_api": "sk_live_[0-9a-z]{32}",
            "google_oauth_id": "[0-9(+-[0-9A-Za-z_]{32}.apps.googleusercontent.com",
            "google_api": "AIza[0-9A-Za-z-_]{35}",
            "google_captcha": "^6[0-9a-zA-Z_-]{39}$",
            "google_oauth": "ya29\\.[0-9A-Za-z\\-_]+",
            "amazon_aws_access_key_id": "AKIA[0-9A-Z]{16}",
            "amazon_mws_auth_token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "amazonaws_url": "s3\\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws.com",
            "facebook_access_token": "EAACEdEose0cBA[0-9A-Za-z]+",                                                                                                                
            "twilio_api_key": "\bSK[0-9a-fA-F]{32}\b",
            "twilio_account_sid": "\bAC[a-zA-Z0-9_\\-]{32}\b",
            "twilio_app_sid": "\bAP[a-zA-Z0-9_\\-]{32}\b",
            "paypal_braintree_access_token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
            "square_oauth_secret": "sq0csp-[ 0-9A-Za-z\\-_]{43}",
            "square_access_token": "sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}",
            "stripe_standard_api": "sk_live_[0-9a-zA-Z]{24}",
            "stripe_restricted_api": "rk_live_[0-9a-zA-Z]{24}",
            "github_access_token": "[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*",
            "private_ssh_key": "-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END PRIVATE KEY-----",
            "private_rsa_key": "-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END RSA PRIVATE KEY-----",
            "gpg_private_key_block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "generic_api_key": "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
            "generic_secret": "[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
            "ip_address": r"(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)",
            #"link_finder": "((?:https?://|www\d{0,3}[.])[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+[\w().=/;,#:@?&~*+!$%{}-]*)",
            "password_in_url": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]"
            }
        compiled_patterns = [(key, re.compile(pattern)) for key, pattern in patterns.items()]

        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_dir, 'known_false_positives.txt')

        with open(file_path, 'r') as f:
            known_false_positives = [re.compile(line.strip()) for line in f if line.strip() and not line.startswith('#')]


        ioc_list = []
        for key, compiled_pattern in compiled_patterns:
            res = list(set(compiled_pattern.findall(text)))
            for i in res:

                if key == "ip_address":
                    if not self.is_real_public_ip(i):
                        continue


                if not any(fp.match(i) for fp in known_false_positives):
                    a = "{}: {}".format(key, i)
                    ioc_list.append(a)
        return ioc_list
