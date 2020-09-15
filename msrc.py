# coding: utf-8
from datetime import datetime
from typing import Dict, List, Optional
import os
import re
import pprint
import json
import logging
import argparse

import requests

logger = logging.getLogger(__name__)

class MSRCApi:
    url = 'https://api.msrc.microsoft.com'

    def __init__(self, key):
        self.headers = {
            'Accept': 'application/json',
            'api-key': key,
        }
        self.params = {'api-version': datetime.now().year}

    def get_cvrf_id_for_cve(self, cve: str):
        url = f"{self.url}/Updates('{cve}')"
        print(url)
        response = requests.get(url, headers=self.headers, params=self.params)
        if response.status_code != 200:
            id = None
        data = response.json()
        id = data['value'][0]['ID']
        return id

    def get_cvrf_id_for_cve2(self, cve: str):
        year = cve.split('-')[1]
        
        CVRFs = []
        for cvrf_meta in self.get_cvrf_by_year(year):
            cvrf = self.get_cvrf_by_id(cvrf_meta['ID'])
            if cvrf.get('Vulnerability'):
                for vuln in cvrf.get('Vulnerability'):
                    if cve == vuln['CVE']:
                        CVRFs.append(cvrf)
        print(f"Found CVRF with cve: {len(CVRFs)}")
        return CVRFs

    def get_knowledge_bases_for_cve(self, cve: str):
        CVRFs = self.get_cvrf_id_for_cve2(cve)
        if CVRFs is None:
            print("No CVRF found")
            return []
        KBs = []
        for cvrf in CVRFs:
            for vuln in cvrf['Vulnerability']:
                if vuln['CVE'] == cve:
                    print(f"Matched {cvrf['DocumentTracking']['Identification']['ID']}")
                    print(f"\twith {vuln['CVE']}")
                    for kb in vuln['Remediations']:
                        KBs.append(kb['Description']['Value'])
        return KBs

    def get_cvrf_by_id(self, cvrf_id):
        #/cvrf/2016-Jan
        if not re.match(r"\d{4}\-\w{3}", cvrf_id):
            raise Exception("ID is not required format: yyyy-M")
        
        url = f"{self.url}/cvrf/{cvrf_id}"
        r = requests.get(url, headers=self.headers, params=self.params)
        if r.status_code != 200:
            logger.error(f"Failed to get update: {cvrf_id}")
            raise Exception
        try:
            data = r.json()
        except Exception as e:
            logger.error(f"Failed to get CVRF: {id} Error: {e}")
            raise(e)
        return data

    def get_cvrf_by_year(self, year):
        if isinstance(year, int):
            year = str(year)

        for cvrf in self.get_all_cvrf():
            if cvrf['ID'].startswith(year):
                yield cvrf

    def get_all_cvrf(self):
        updates_query = f"{self.url}/Updates"
        r = requests.get(updates_query, headers=self.headers, params=self.params)
        if r.status_code != 200:
            raise SystemExit("Failed to get updates")
        data = r.json()
        values = data['value']
        for value in values:
            # Example:
            # {'ID': '2019-Nov', 'Alias': '2019-Nov', 'DocumentTitle': 'November 2019 Security Updates', 'Severity': None, 'InitialReleaseDate': '2019-11-12T08:00:00Z', 'CurrentReleaseDate': '2020-02-03T08:00:00Z', 'CvrfUrl': 'https://api.msrc.microsoft.com/cvrf/2019-Nov?api-Version=2020'}
            yield value

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('cve', help='CVE ex) CVE-2017-4534')
    parser.add_argument('-k', '--key',
        help="MSRC Key, You cand add Environment Variable as 'MSRC_KEY'")
    options = parser.parse_args()
    key = os.getenv('MSRC_KEY', None) or options.key
    msrc = MSRCApi(key)

    options.cve.upper().startswith('CVE'):
    kbs = msrc.get_knowledge_bases_for_cve(options.cve)
    if len(kbs) == 0:
        print("No KBs found")
        raise SystemExit()
    kbs = list(set(kbs))
    for kb in kbs:
        print("KB" +kb)
    query = "(" + "|".join([f".*{kb}.*" for kb in kbs]) + ")"
    print(f"Get Computer name from all machines Applicable Patches matching \"{query}\"")
        
    raise SystemExit()
