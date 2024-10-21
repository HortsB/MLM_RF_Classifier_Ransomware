import os
import sys
import argparse
import array
import math
import pickle
import pefile
import hashlib
import pandas as pd
import numpy as np
import joblib
import urllib
import urllib3
import json
import requests
from requests.auth import HTTPBasicAuth
from termcolor import colored, cprint
import colorama
import base64
import webbrowser


class ExtractFeatures():

    def __init__(self, file):
        self.file = file

    def get_md5(self, file):
        md5 = hashlib.md5()
        with open(file, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
            return md5.hexdigest()

    def get_fileinfo(self, file):
        features = {}
        pe = pefile.PE(file, fast_load=True)
        features['Machine'] = pe.FILE_HEADER.Machine
        features['DebugSize'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size
        features['DebugRVA'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress
        features['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
        features['MajorOSVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        features['ExportRVA'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress
        features['ExportSize'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size
        features['IatVRA'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress
        features['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        features['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
        features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        features['ResourceSize'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size

        return features

class RepChecker():
    def __init__(self):
        vtapi = base64.b64decode(
            'M2FlNzgwMDU5MTE3ZThkYzdmNjA5YjVlOWU1Y2JmOTRkMGJkNTA3NTAyNzI3NWJiOTM3YTg0NGEwYTYzNDNlYQ==')
        self.vtapi = vtapi.decode('utf-8')
        self.vtbase = 'https://www.virustotal.com/vtapi/v2/file/report'
        self.http = urllib3.PoolManager()
        self.tcbase = 'http://www.threatcrowd.org/searchApi/v2/file/report/?resource='
        hapi = base64.b64decode(
            'OGtzMDhrc3NrOGNja3Nnd3dnY2NnZzRzOG8wczA0Y2tzODA4c2NjYzAwZ2s0a2trZzRnc2s4Zzg0OGc4b2NvNA==')
        self.hapi = hapi.decode('utf-8')
        hsecret = base64.b64decode('MTFhYjc1OTMxZGYzOWFjMmVjYmI3ZGNhNmI1MzYxMmE3YmU4ZjM3MTM5YTAwY2Nm')
        self.hsecret = hsecret.decode('utf-8')
        self.hbase = 'https://www.hybrid-analysis.com/api/scan/'

    def get_virus_total(self, md5):
        params = {'apikey': self.vtapi, 'resource': md5}
        data = urllib.parse.urlencode(params).encode("utf-8")
        r = requests.get(self.vtbase, params=params)
        return r.json()

    def get_threatcrowd(self, md5):
        r = requests.get(self.tcbase)
        return r.json()

    def get_hybrid(self, md5):
        headers = {'User-Agent': 'Falcon'}
        query = self.hbase + md5
        r = requests.get(query, headers=headers, auth=HTTPBasicAuth(self.hapi, self.hsecret))
        return r.json()

def parse(file, features, display, virustotal, threatcrowd, hybridanalysis):
    get_data = RepChecker()
    md5 = ExtractFeatures(file)
    md5_hash = md5.get_md5(file)

    if display:
        print("[*] Printing extracted file features...")
        print("\n\tMD5: ", md5_hash)
        print("\tDebug Size: ", features[0])
        print("\tDebug RVA: ", features[1])
        print("\tMajor Image Version:", features[2])
        print("\tMajor OS Version:", features[3])
        print("\tExport RVA:", features[4])
        print("\tExport Size:", features[5])
        print("\tIat RVA: ", features[6])
        print("\tMajor Linker Version: ", features[7])
        print("\tMinor Linker Version", features[8])
        print("\tNumber Of Sections: ", features[9])
        print("\tSize Of Stack Reserve: ", features[10])
        print("\tDll Characteristics: ", features[11])

    if virustotal:
        print("[+] Running Virus Total reputation check...\n")
        data = get_data.get_virus_total(md5_hash)

        if data['response_code'] == 0:
            print("[-] The file %s with MD5 hash %s was not found in Virus Total" % (os.path.basename(file), md5_hash))
        else:
            print("\tResults for file %s with MD5 %s:" % (os.path.basename(file), md5_hash))
            if data['positives'] == 0:
                print("\n\tDetected by: ", colored(str(data['positives']), 'green'), '/', data['total'], '\n')
            elif data['positives'] > 0 and data['positives'] <= 25:
                print("\n\tDetected by: ", colored(str(data['positives']), 'yellow'), '/', data['total'], '\n')
            else:
                print("\n\tDetected by: ", colored(str(data['positives']), 'red'), '/', data['total'], '\n')

            av_firms = []
            malware_names = []
            fmt = '%-4s%-23s%s'

            if data['positives'] > 0:
                for scan in data['scans']:
                    if data['scans'][scan]['detected'] == True:
                        av_firms.append(scan)
                        malware_names.append(data['scans'][scan]['result'])

                print('\t', fmt % ('', 'AV Firm', 'Malware Name'))
                for i, (l1, l2) in enumerate(zip(av_firms, malware_names)):
                    print('\t', fmt % (i, l1, l2))
                if data['permalink']:
                    print("\n\tVirus Total Report: ", data['permalink'], '\n')

            if data['positives'] == 0:
                print(
                    colored('[*] ', 'green') + "Virus Total has found the file %s " % os.path.basename(file) + colored(
                        "not malicious.", 'green'))
                if data['permalink']:
                    print("\n\tVirus Total Report: ", data['permalink'], '\n')
            elif data['positives'] > 0 and data['positives'] <= 25:
                print(colored('[*] ', 'red') + "Virus Total has found the file %s " % os.path.basename(file) + colored(
                    "has malicious properties.\n", 'yellow'))
            else:
                print(colored('[*] ', 'red') + "Virus Total has found the file %s " % os.path.basename(file) + colored(
                    "is malicious.\n", 'red'))

    if threatcrowd:
        fmt = '%-4s%-23s'
        print("[+] Retrieving information from Threat Crowd...\n")
        data = get_data.get_threatcrowd(md5_hash)

        if data['response_code'] == "0":
            print("[-] The file %s with MD5 hash %s was not found in Threat Crowd.\n" % (
            os.path.basename(file), md5_hash))
        else:
            print("\n\tSHA1: ", data['sha1'])
            if data['ips']:
                print('\n\t', fmt % ('', 'IPs'))
                for i, ip in enumerate((data['ips'])):
                    print('\t', fmt % (i + 1, ip))

            if data['domains']:
                print('\n\t', fmt % ('', 'Domains'))
                for i, domain in enumerate((data['domains'])):
                    print('\t', fmt % (i + 1, domain))

            if data['scans']:
                if data['scans'][1:]:
                    print('\n\t', fmt % ('', 'Antivirus'))
                    for i, scan in enumerate(data['scans'][1:]):
                        print('\t', fmt % (i + 1, scan))

            print('\n\tThreat Crowd Report: ', data['permalink'], '\n')

    if hybridanalysis:
        data = get_data.get_hybrid(md5_hash)
        fmt = '%-4s%-23s'

        print("[+] Retrieving information from Hybrid Analysis...\n")

        if not data['response']:
            print("[-] The file %s with MD5 hash %s was not found in Hybrid Analysis." % (
            os.path.basename(file), md5_hash), '\n')
        else:
            try:
                print('\t', data['response'][0]['submitname'])
            except:
                pass

            print('\tSHA256:', data['response'][0]['sha256'])
            print('\tSHA1: ', data['response'][0]['sha1'])
            print('\tThreat Level: ', data['response'][0]['threatlevel'])
            print('\tThreat Score: ', data['response'][0]['threatscore'])
            print('\tVerdict: ', data['response'][0]['verdict'])

            try:
                print('\tFamily: ', data['response'][0]['vxfamily'])
            except:
                pass
            try:
                if data['response'][0]['classification_tags']:
                    print('\n\t', fmt % ('', 'Class Tags'))
                    for i, tag in enumerate(data['response'][0]['classification_tags']):
                        print('\t', fmt % (i + 1, tag))
                else:
                    print("\tClass Tags: No Classification Tags.")
            except:
                pass
            try:
                if data['response'][0]['compromised_hosts']:
                    print('\n\t', fmt % ('', 'Compromised Hosts'))
                    for i, host in enumerate(data['response'][0]['compromised_hosts']):
                        print('\t', fmt % (i + 1, host))
                else:
                    print('\t\nCompromised Hosts: No Compromised Hosts.')
            except:
                pass
            try:
                if data['response'][0]['domains']:
                    print('\n\t', fmt % ('', 'Domains'))
                    for i, domain in enumerate(data['response'][0]['domains']):
                        print('\t', fmt % (i + 1, domain))
                else:
                    print('\tDomains: No Domains.')
            except:
                pass
            try:
                if data['response'][0]['total_network_connections']:
                    print('\tNetwork Connections: ', data['response'][0]['total_network_connections'])
                else:
                    print('\n\tNetwork Connections: No Network Connections')
            except:
                pass
            try:
                if data['response'][0]['families']:
                    print('\tFamilies: ', data['response'][0]['families'])
            except:
                pass

            if data['response'][0]['verdict'] == "malicious":
                print(colored('\n[*] ', 'red') + "Hybrid Analysis has found that the file %s " % os.path.basename(
                    file) + colored("is malicious.\n", 'red'))
            else:
                print(colored('\n[*] ', 'green') + "Hybrid Analysis has found that the file %s " % os.path.basename(
                    file) + colored("is not malicious.\n", 'green'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', nargs='?', help="File To Parse", )
    parser.add_argument('-d', '--displayfeatures', action='store_true', dest='display',
                        help='Display extracted file features.')
    parser.add_argument('-v', "--virustotal", action='store_true', dest='virustotal',
                        help="Run with Virus Total check.")
    parser.add_argument('-t', '--threatcrowd', action='store_true', dest='threatcrowd',
                        help="Run with Threat Crowd check.")
    parser.add_argument('-z', '--hybridanalysis', action='store_true', dest='hybridanalysis',
                        help="Run Hybrid Analysis check.")
    args = parser.parse_args()
    colorama.init()

    clf = joblib.load(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'classifier/classifier.pkl'))

    features = pickle.loads(open(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'classifier/features.pkl'),
        'rb').read())

    get_features = ExtractFeatures(args.file)
    data = get_features.get_fileinfo(args.file)
    feature_list = list(map(lambda x: data[x], features))
    print("\n[+] Analizador funcionando...\n")
    result = clf.predict([feature_list])[0]

    if result == 1:
        print(
            colored('[*] ', 'green') + "El archivo %s se identificó como " % os.path.basename(sys.argv[1]) + colored(
                'benigno.\n', 'green'))
    else:
        print(colored('[*] ', 'red') + "El archivo %s se identificó como " % os.path.basename(sys.argv[1]) + colored(
            'ransomware.\n', 'red'))

    if args.display or args.virustotal or args.threatcrowd or args.hybridanalysis:
        parse(args.file, feature_list, args.display, args.virustotal, args.threatcrowd, args.hybridanalysis)


if __name__ == '__main__':
    main()
