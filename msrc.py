# coding: utf-8
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional
import os
import re
import pprint
import json
import logging
import argparse

import requests

logger = logging.getLogger(__name__)

@dataclass
class Note:
    Title: str
    Type: int
    Ordinal: str
    Value: str

@dataclass
class Vulnerability:
    Title: Dict
    Notes: List[Note]
    DiscoveryDateSpecified: bool 
    ReleaseDateSpecified: bool
    Ordinal: str
    RevisionHistory: List[Dict]
    CVE: str 
    ProductStatuses: List[Dict]
    Threats: List[Dict]
    CVSSScoreSets: List
    Remediations: List
    Acknowledgments: List

    def __repr__(self):
        return f"Vulnerability(Title: {self.Title['Value']}, CVE: {self.CVE})"

    def __str__(self):
        return f"Title: {self.Title['Value']}, CVE: {self.CVE}, Products: {self.ProductStatuses[0]['ProductID'].values()}"

@dataclass
class Product:
    ProductID: str
    Value: str

@dataclass(init=False)
class CVRF:
    ID: str
    DocumentTitle: str
    DocumentType: str
    DocumentPublisher : Dict[str, Dict]
    DocumentTracking: Dict[str, Dict]
    DocumentNotes: List[Dict]
    ProductTree: Dict[str, str]
    Vulnerabilities: List[Vulnerability]

    @classmethod
    def init(cls, id, raw):
        obj = cls()
        obj.ID = id
        obj.DocumentTitle = raw.get("DocumentTitle").get("Value")
        obj.DocumentType = raw.get("DocumentType").get("Value")
        obj.DocumentPublisher = raw.get("DcoumentPublisher")
        obj.DocumentTracking = raw.get("DcoumentTracking")
        obj.DocumentNotes = raw.get("DcoumentNotes")
        obj.ProductTree = obj.set_products(raw.get("ProductTree"))
        obj.Vulnerabilities = []
        for vuln in raw.get("Vulnerability", []):
            v = Vulnerability(**vuln)
            v.ProductStatuses[0]['ProductID'] = {pid: obj.ProductTree[pid] for pid in v.ProductStatuses[0]['ProductID']}
            obj.Vulnerabilities.append(v)
        return obj
    
    def __repr__(self):
        return f"CVRF(ID: {self.ID})"

    def __str__(self):
        return f"CVRF(ID: {self.ID})"

    def set_products(self, data):
        products = {}
        for product in data.get("FullProductName", []):
            products[product['ProductID']] = product['Value']

        for branch in data.get("Branch", []):
            if not branch.get('Items'):
                break
            for item in branch['Items'][0]['Items']:
                products[product['ProductID']] = product['Value']
        return products

    def is_security(self) -> bool:
        if self.DocuemntType['Value'] == 'Security Update':
            return True
        return False

    def affected(self, products: List[str]) -> List[Vulnerability]:
        vulns = []
        for vuln in self.Vulnerabilities:
            found = False
            for p in vuln.ProductStatuses[0]['ProductID'].values():
                for name in products:
                    if name.upper() in p.upper():
                        found = True
                        break
                if found:
                    vulns.append(vuln)
                    break
        return vulns


@dataclass
class SecurityUpdate:
    ID: str
    Alias: str = field(repr=False)
    DocumentTitle: str
    Severity: str
    InitialReleaseDate: str = field(repr=False)
    CurrentReleaseDate: str
    CvrfUrl: str = field(repr=False)
    Cvrf: CVRF = field(repr=False, default=None)

    def summary(self):
        return f"{self.DocumentTitle}({self.ID}): {len(self.Cvrf.Vulnerability)}"

    @classmethod
    def load(cls, filename: str):
        obj = cls()
        with open(filename) as f:
            data = json.load(filename)
            obj.ID = data['ID'] 

    def dump(self, filename: str=None):
        if filename is None:
            filename = f"{self.DocumentTitle.replace(' ', '_')}.json"
        data = {
            'ID': self.ID,
            'title': self.DocumentTitle,
            'ReleaseDate': self.CurrentReleaseDate,
        }
        if self.Cvrf:
            data['cvrf'] = asdict(self.Cvrf)
        with open(filename, 'w') as f:
           f.write(json.dumps(data, indent=2))


class MSRCApi:
    url = 'https://api.msrc.microsoft.com'

    def __init__(self, key):
        self.headers = {
            'Accept': 'application/json',
            'api-key': key,
        }
        self.params = {'api-version': datetime.now().year}

    def cvrf(self, id):
        #/cvrf/2016-Jan
        if not re.match(r"\d{4}\-\w{3}", id):
            raise Exception("ID is not required format: yyyy-M")
        cvrf_query = f"{self.url}/cvrf/{id}"
        r = requests.get(cvrf_query, headers=self.headers, params=self.params)
        if r.status_code != 200:
            logger.error(f"Failed to get update: {ID}")
            raise Exception
        try:
            data = r.json()
            logger.debug(f"Init {id}")
            cvrf = CVRF.init(id, data)
        except Exception as e:
            logger.error(f"Failed to get CVRF: {id} Error: {e}")
            raise(e)
        return cvrf

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

    def updates(self):
        updates_query = f"{self.url}/Updates"
        r = requests.get(updates_query, headers=self.headers, params=self.params)
        if r.status_code != 200:
            raise SystemExit("Failed to get updates")
        data = r.json()
        data['value']
        updates = [SecurityUpdate(**update) for update in r.json().get('value')]
        for update in updates:
            print(update.CvrfUrl)
            r = requests.get(update.CvrfUrl, headers=self.headers, params=self.params)
            if r.status_code != 200:
                logger.error(f"Failed to get update: {ID}")
                continue
            try:
                data = r.json()
                logger.debug(f"Init {update.ID}")
                cvrf = CVRF.init(update.ID, data)
                update.Cvrf = cvrf
                logger.debug(f"{update}")
            except Exception as e:
                logger.error(f"Failed to get CVRF: {update.ID} Error: {e}")
                raise(e)
        return updates

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('id')
    parser.add_argument('--clear-cache')
    parser.add_argument('-k', '--key',
        help="MSRC Key")
    parser.add_argument('-D', '--dump', action='store_true',
        help="Dump result to file")
    options = parser.parse_args()
    key = os.getenv('MSRC_KEY', None) or options.key
    msrc = MSRCApi(key)

    updates = []
    if options.id.upper() in ['*', 'ALL']:
        msrc.get_all_cvrf()
        raise SystemExit()
    elif options.id.upper().startswith('CVE'):
        kbs = msrc.get_knowledge_bases_for_cve(options.id)
        if len(kbs) == 0:
            print("No KBs found")
            raise SystemExit()
        kbs = list(set(kbs))
        for kb in kbs:
            print("KB" +kb)
        query = "(" + "|".join([f".*{kb}.*" for kb in kbs]) + ")"
        print(f"Get Computer name from all machines Applicable Patches matching \"{query}\"")
            
        raise SystemExit()
    else:
        updates = [msrc.cvrf(options.id)]

    for update in updates:
        print(pprint.pformat(update))
        #for v in update.Vulnerabilities:
        #    print('CVE: %s' % v.CVE)
        for vuln in update.affected(['Windows 7', 'Windows 10', 'Windows 2016', 'Windows 2008', 'Windows 2019']):
            print(f"{vuln.CVE}, {vuln.Title['Value']}")
        if options.dump:
            update.dump()
