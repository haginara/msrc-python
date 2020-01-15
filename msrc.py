# coding: utf-8
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
        for product in data.get("FullProductName"):
            products[product['ProductID']] = product['Value']

        for branch in data.get("Branch"):
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
        self.params = {'api-version': 2020}

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

    def updates(self):
        updates_query = f"{self.url}/updates"
        r = requests.get(updates_query, headers=self.headers, params=self.params)
        if r.status_code != 200:
            raise SystemExit("Failed to get updates")
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
    parser.add_argument('-k', '--key',
        help="MSRC Key")
    parser.add_argument('-D', '--dump', action='store_true',
        help="Dump result to file")

    options = parser.parse_args()
    key = os.getenv('MSRC_KEY', None) or options.key
    msrc = MSRCApi(key)
    updates = []
    if options.id.upper() in ['*', 'ALL']:
        updates = [update for update in msrc.updates()]
    else:
        updates = [msrc.cvrf(options.id)]

    for update in updates:
        print(pprint.pformat(update))
        #for v in update.Vulnerabilities:
        #    print(v.CVE)
        for vuln in update.affected(['Windows 10', 'Windows 2016', 'Windows 2008', 'Windows 2019']):
            print(f"{vuln.CVE}, {vuln.Title['Value']}")
        if options.dump:
            update.dump()
