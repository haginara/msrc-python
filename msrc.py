# coding: utf-8
from datetime import datetime
from typing import Dict, List, Optional
import os
import re
import logging
import argparse

import requests

logger = logging.getLogger(__name__)


class MSRCApi:
    url = "https://api.msrc.microsoft.com"

    def __init__(self, key):
        self.headers = {
            "Accept": "application/json",
            "api-key": key,
        }
        self.params = {"api-version": datetime.now().year}

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
        print(f"Matched CVRF: {cvrf['DocumentTracking']['Identification']['ID']}")
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
            # {'ID': '2019-Nov', 'Alias': '2019-Nov', 'DocumentTitle': 'November 2019 Security Updates', 'Severity': None, 'InitialReleaseDate': '2019-11-12T08:00:00Z', 'CurrentReleaseDate': '2020-02-03T08:00:00Z', 'CvrfUrl': 'https://api.msrc.microsoft.com/cvrf/2019-Nov?api-Version=2020'}
            yield value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cve", help="CVE ex) CVE-2017-0144")
    parser.add_argument(
        "-k", "--key", help="MSRC Key, You cand add Environment Variable as 'MSRC_KEY'"
    )
    options = parser.parse_args()
    key = os.getenv("MSRC_KEY", None) or options.key
    msrc = MSRCApi(key)

    if not options.cve.upper().startswith("CVE-"):
        raise SystemExit("CVE should start with CVE-")

    kbs = msrc.get_knowledge_bases_by_cve(options.cve)
    if len(kbs) == 0:
        print("No KBs found")
        raise SystemExit()
    kbs = list(set(kbs))
    for kb in kbs:
        print("KB" + kb)


if __name__ == "__main__":
    main()
