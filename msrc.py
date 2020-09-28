# coding: utf-8
from datetime import datetime
import os
import re
import logging
import argparse

import requests

__version_info__ = (0, 0, 1)
__version__ = '.'.join(map(str, __version_info__))


logger = logging.getLogger(__name__)


def get_product_name_by_id(cvrf, pid):
    """ Get product full name by product id

    Args:
        cvrf (dict): CVRF data
        pid (int): ProductID

    Returns:
        Full Product Name (str) or None
    """
    products = cvrf['ProductTree']['FullProductName']

    for p in products:
        if p['ProductID'] == pid:
            return p['Value']
    return None


class MSRCApi:
    url = "https://api.msrc.microsoft.com"

    def __init__(self, key):
        self.headers = {
            "Accept": "application/json",
            "api-key": key,
        }
        self.params = {"api-version": datetime.now().year}

    def get_cvrf_by_month(self, year_month: str):
        """Get CVRF with year_month

        Args:
            year_month (str): YYYY-mmm format

        Returns:
            CVRF (list(dict)) or None
        """
        url = f"{self.url}/Updates('{year_month}')"
        logger.debug(url)
        response = requests.get(url, headers=self.headers, params=self.params)
        if response.status_code != 200:
            raise Exception("Failed to get CVRF")
        data = response.json()
        return data

    def get_cvrf_by_cve(self, cve: str):
        """Get CVRF with CVE
        Notice: This API is not working correctly.

        Args:
            cve (str): CVE ID
        Returns:
            CVRF (dict) or None

        """
        url = f"{self.url}/Updates('{cve}')"
        logger.debug(url)
        response = requests.get(url, headers=self.headers, params=self.params)
        if response.status_code != 200:
            raise Exception("Failed to get CVRF")
        data = response.json()
        cvrf = None
        if len(data["value"]) > 2:
            cvrf = self._get_cvrf_id_by_cve(cve)
        else:
            cvrf = self.get_cvrf_by_id(data["value"][0]["ID"])
        return cvrf

    def _get_cvrf_id_by_cve(self, cve: str):
        """Get CVRF ID with CVE
        Slow version to get CVRF id from all CVRF list.
        It checks year part from CVE and only search with same year with CVE

        Args:
            cve (str): CVE ID
        Returns:
            CVRF (dict) or None

        """
        year = cve.split("-")[1]
        for cvrf_meta in self.get_cvrf_by_year(year):
            cvrf = self.get_cvrf_by_id(cvrf_meta["ID"])
            if cvrf is None:
                return None
            if cvrf.get("Vulnerability"):
                for vuln in cvrf.get("Vulnerability"):
                    if cve == vuln["CVE"]:
                        return cvrf
        return None

    def get_knowledge_bases_by_cve(self, cve: str):
        """Get Knowledge Base(KB) from CVE

        Args:
            cve (str): CVE ID

        Returns:
            List of KBs

        """
        cvrf = self.get_cvrf_by_cve(cve)
        if cvrf is None:
            logger.debug("No CVRF found")
            return []
        print(f"Matched CVRF: {cvrf['DocumentTracking']['Identification']['ID']['Value']}")
        KBs = []
        for vuln in cvrf["Vulnerability"]:
            if vuln["CVE"] == cve:
                for kb in vuln["Remediations"]:
                    KBs.append(kb["Description"]["Value"])
        return KBs

    def get_cvrf_by_id(self, cvrf_id):
        """Get CVRF data by ID

        Args:
            cvrf_id (str): CVRF Id

        Returns:
            CVRF Data

        Raises:

        """
        # Format /cvrf/2016-Jan
        if not re.match(r"\d{4}\-\w{3}", cvrf_id):
            raise Exception("ID is not required format: yyyy-M")

        url = f"{self.url}/cvrf/{cvrf_id}"
        r = requests.get(url, headers=self.headers, params=self.params)
        if r.status_code != 200:
            raise Exception(f"Failed to get update: {cvrf_id}")
        try:
            data = r.json()
        except Exception as e:
            raise Exception(f"Failed to get CVRF: {id} Error: {e}")
        return data

    def get_cvrf_by_year(self, year):
        """Get CVRFs with year

        Args:
            year (int/str): Target year

        Returns:
            list of CVRFs
        """
        if isinstance(year, int):
            year = str(year)

        for cvrf in self.get_all_cvrf():
            if cvrf["ID"].startswith(year):
                yield cvrf

    def get_cves_by_cvrf(self, cvrf_id):
        """Get CVEs by CVRF ID

        Args:
            cvrf_id (str): CVRF id

        Returns:
            CVEs
        """
        cvrf = self.get_cvrf_by_id(cvrf_id)
        CVEs = []
        if 'Vulnerability' in cvrf:
            for vuln in (cvrf['Vulnerability']):
                title = vuln['Title'].get('Value', 'None')
                CVEs.append((vuln['CVE'], title))
        return CVEs

    def get_all_cvrf(self):
        """Get all CVRFs

        Returns:
            List of CVRFs
        """
        updates_query = f"{self.url}/Updates"
        r = requests.get(updates_query, headers=self.headers, params=self.params)
        if r.status_code != 200:
            raise SystemExit("Failed to get updates")
        data = r.json()
        values = data["value"]
        for value in values:
            # Example:
            # {'ID': '2019-Nov', 'Alias': '2019-Nov', 'DocumentTitle': 'November 2019 Security Updates',
            #   'Severity': None, 'InitialReleaseDate': '2019-11-12T08:00:00Z',
            #   'CurrentReleaseDate': '2020-02-03T08:00:00Z',
            #   'CvrfUrl': 'https://api.msrc.microsoft.com/cvrf/2019-Nov?api-Version=2020'}
            yield value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', action='version', version=__version__)
    parser.add_argument("-k", "--key", help="MSRC Key, You cand add Environment Variable as 'MSRC_KEY'")
    parser.add_argument("search", help="CVE ex) CVE-2017-0144, CVRF ex) 2020-Sep")
    options = parser.parse_args()
    key = os.getenv("MSRC_KEY", None) or options.key
    msrc = MSRCApi(key)

    search = options.search
    if search.upper().startswith("CVE"):
        kbs = msrc.get_knowledge_bases_by_cve(options.search)
        if len(kbs) == 0:
            raise SystemExit("No KBs found")
        kbs = list(set(kbs))
        for kb in kbs:
            print("KB" + kb)
    elif re.match(r"\d{4}\-\w{3}", search):
        cves = msrc.get_cves_by_cvrf(search)
        for cve in cves:
            print(cve[0], cve[1])
    else:
        raise SystemExit(f"CVE should start with CVE- or yyyy-m format, {search}")


if __name__ == "__main__":
    main()
