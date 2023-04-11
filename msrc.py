# coding: utf-8
import re
import logging
import argparse

import requests

__version_info__ = (0, 0, 2)
__version__ = ".".join(map(str, __version_info__))


logger = logging.getLogger(__name__)

msrc_url = "https://api.msrc.microsoft.com"
version = "2.0"


def get_value(data, key, default=None):
    """
    Args:
        data (dict): Dictionary data
        key (str): key with '.' ex) a.b or a.b.1.c
        default (Any: None): Default value when the key is not available
    """
    try:
        for k in key.split("."):
            if k.isdigit():
                idx = int(k)
                data = data[idx]
            else:
                data = data.get(k, default)
    except Exception as e:
        if default:
            return default
        raise e
    return data


def get_product_name_by_id(cvrf, pid):
    """Get product full name by product id

    Args:
        cvrf (dict): CVRF data
        pid (int): ProductID

    Returns:
        Full Product Name (str) or None
    """
    products = cvrf["ProductTree"]["FullProductName"]

    for p in products:
        if p["ProductID"] == pid:
            return p["Value"]
    return None


class JsonDict(object):
    def __init__(self, data):
        self.data = data

    def get_value(self, key, default=None):
        return get_value(self.data, key, default)

    def __repr__(self):
        return self.__str__()


class Product(JsonDict):
    def __init__(self, data):
        super(Product, self).__init__(data)

        self.product_id = self.get_value("ProductID")
        self.name = self.get_value("Value")

    def __str__(self):
        return f"Product<{self.name}>"


class Remediation(JsonDict):
    def __init__(self, data):
        super(Remediation, self).__init__(data)

        self.type = self.get_value("Type")
        if self.type == 0:
            self.description = self.get_value("Description.Value")
            self.kb = None
            self.url = None
            self.products = []
        else:
            self.kb = ""
            if (
                self.get_value("Description.Value")
                and self.get_value("Description.Value", "").isdigit()
            ):
                self.kb = "KB" + self.get_value("Description.Value")
            self.url = self.get_value("URL")
            self.products = self.get_value("ProductID")

    def __str__(self):
        return f"Remediatin<{self.kb}>"


class Vulnerability(JsonDict):
    def __init__(self, data):
        super(Vulnerability, self).__init__(data)

        self.title = self.get_value("Title.Value")
        self.cve = self.get_value("CVE")
        self.threats = self.get_value("Threats")
        self.products = self.get_value("ProductStatuses.0.ProductID")
        self.remediations = [
            Remediation(item) for item in self.get_value("Remediations")
        ]

    def __str__(self):
        return f"Vulnerability<{self.cve}>"


class CVRF(JsonDict):
    def __init__(self, data):
        super(CVRF, self).__init__(data)

        self.title = self.get_value("DocumentTitle.Value")
        self.type = self.get_value("DocumentType.Value")
        self.publisher_contact = self.get_value(
            "DocumentPublisher.ContactDetails.Value"
        )
        self.id = self.get_value("DocumentTracking.Identification.ID.Value")
        self.release_date = self.get_value("DocumentTracking.InitialReleaseDate")
        self.updated_date = self.get_value("DocumentTracking.CurrentReleaseDate")

        self.vulnerabilites = [
            Vulnerability(vuln) for vuln in self.get_value("Vulnerability", [])
        ]  # Hash is better ?
        self.products = [
            Product(product)
            for product in self.get_value("ProductTree.FullProductName", [])
        ]

    def __str__(self):
        return f"CVRF<{self.title}>"

    def get_cve(self, cve_id):
        """
        Find and get a CVE data
        """
        for vuln in self.vulnerabilites:
            if vuln.cve == cve_id:
                return vuln


def get_cvrf(cvrf: str):
    """
    Get detailed Microsoft security udpates, formatted according to the Common Vulnerabillity Reporting Framewaork.

    Args:
        cvrf (str): cvrf id (yyyy-mmm)
    return
    """

    url = f"{msrc_url}/cvrf/v{version}/cvrf/{cvrf}"
    logger.debug(url)
    response = requests.get(url, headers={"Accept": "application/json"})
    if response.status_code != 200:
        raise Exception("Failed to get CVRF, %d" % (response.status_code))
    data = response.json()
    return CVRF(data)


def get_cvrfs(query=None):
    """
    Get a list of Microsoft security updates
    """
    url = f"{msrc_url}/cvrf/v{version}/"
    url += f"Updates('{query}')" if query else "updates"
    logger.debug(url)
    response = requests.get(url, headers={"Accept": "application/json"})
    if response.status_code != 200:
        raise Exception(
            "Failed to get a list of MS security updates, " f"{response.status_code}"
        )
    cvrfs = response.json().get("value", [])
    return cvrfs


def get_updates(update_id=None, vul_id=None, year=None):
    """
    Get a list of Microsoft security updates
    """
    query = update_id or vul_id or year or None
    cvrfs = get_cvrfs(query)

    if vul_id:
        cvrf = get_cvrf(cvrfs[0]["ID"])
        return cvrf.get_cve(vul_id)
    return [get_cvrf(cvrf["ID"]) for cvrf in cvrfs]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v", "--version",
        action="version", version=__version__
    )
    parser.add_argument(
        "search",
        help="CVE ex) CVE-2017-0144, CVRF ex) 2020-Sep, KB ex) KB5014699"
    )
    options = parser.parse_args()

    search = options.search
    if search.upper().startswith("CVE"):
        cve = get_updates(vul_id=search)
        print(cve)
        for remediation in cve.remediations:
            if remediation.type == 5:
                print(remediation.kb, remediation.url)
    elif search.upper().startswith("KB"):
        cvrfs = get_cvrfs()
        for cvrf in cvrfs:
            cvrf = get_cvrf(cvrf["ID"])
            for vuln in cvrf.vulnerabilites:
                for remediation in vuln.remediations:
                    if remediation.kb == search.upper():
                        print(f"{remediation.kb}: {remediation.url}")
                        return
    elif re.match(r"\d{4}\-\w{3}", search):
        cvrf = get_cvrf(search)
        for vuln in cvrf.vulnerabilites:
            print(f"{vuln.cve} {vuln.title}")
    else:
        raise SystemExit(f"CVE should start with CVE- or yyyy-m format, {search}")


if __name__ == "__main__":
    main()
