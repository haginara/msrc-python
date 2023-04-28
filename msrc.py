# coding: utf-8
from dataclasses import dataclass, field, InitVar
from typing import List, Dict, Any, Optional, Union, Tuple
from functools import reduce
import re
import logging
import argparse

import requests

__version_info__ = (0, 0, 2)
__version__ = ".".join(map(str, __version_info__))


logger = logging.getLogger(__name__)


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

""" Default Type """
@dataclass
class CommonType:
    Value: Optional[str] = ""


@dataclass
class CVRF:
    DocumentTitle: Optional[CommonType] = None

    title: str = field(default="", metadata={"path": "DocumentTitle.Value"})
    type_: str = field(default="", metadata={"path": "DocumentType.Value"})
    publisher_contact: str = field(
        default="", metadata={"path": "DocumentPublisher.ContactDetails.Value"}
    )
    id_: str = field(
        default="", metadata={"path": "DocumentTracking.Identification.ID.Value"}
    )
    release_date: str = field(
        default="", metadata={"path": "DocumentTracking.InitialReleaseDate"}
    )
    updated_date: str = field(
        default="", metadata={"path": "DocumentTracking.CurrentReleaseDate"}
    )
    vulnerabilites: List[Vulnerability] = field(
        default_factory=list, metadata={"path": "Vulnerability"}
    )
    products: List[Product] = field(
        default_factory=list, metadata={"path": "ProductTree.FullProductName"}
    )


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


@dataclass
class Product:
    product_id: str
    name: str


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


@dataclass
class Remediation:
    type_: str
    description: str
    kb: Optional[str] = None
    url: Optional[str] = None
    products: Optional[List] = field(default_factory=list)
    kb: Optional[str] = ""


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


@dataclass
class Vulnerability:
    title: str
    cve: str
    threats: List[str] = field(default_factory=list)
    products: List[str] = field(default_factory=list)
    remediations: List[Remediation] = field(default_factory=list)


@dataclass
class CVRF:
    title: str = field(default="", metadata={"path": "DocumentTitle.Value"})
    type_: str = field(default="", metadata={"path": "DocumentType.Value"})
    publisher_contact: str = field(
        default="", metadata={"path": "DocumentPublisher.ContactDetails.Value"}
    )
    id_: str = field(
        default="", metadata={"path": "DocumentTracking.Identification.ID.Value"}
    )
    release_date: str = field(
        default="", metadata={"path": "DocumentTracking.InitialReleaseDate"}
    )
    updated_date: str = field(
        default="", metadata={"path": "DocumentTracking.CurrentReleaseDate"}
    )
    vulnerabilites: List[Vulnerability] = field(
        default_factory=list, metadata={"path": "Vulnerability"}
    )
    products: List[Product] = field(
        default_factory=list, metadata={"path": "ProductTree.FullProductName"}
    )
    raw: InitVar[Dict[str, Any]] = None

    def __post_init__(self, raw):
        if raw:
            for fieldname, field in self.__dataclass_fields__.items():
                if not hasattr(field, "metadata"):
                    continue
                if "path" not in field.metadata:
                    continue
                setattr(self, fieldname, get_value(raw, field.metadata["path"]))

    def get_cve(self, cve_id: str) -> Union[Vulnerability, None]:
        """
        Find and get a CVE data
        """
        for vuln in self.vulnerabilites:
            if vuln.cve == cve_id:
                return vuln
        return None


class MSRC(object):
    msrc_url: str = "https://api.msrc.microsoft.com"
    version: str = "v2.0"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    def request(
        self,
        method: str,
        path: str,
        headers: Optional[Dict] = None,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
    ) -> Any:
        method = method.upper()
        if method not in ("GET", "POST"):
            raise Exception("GET, POST only allowed")
        url = f"{self.msrc_url}/cvrf/{self.version}/{path}"
        res = self.session.request(
            method, url, headers=headers, params=params, data=data
        )
        if res.status_code != 200:
            raise Exception(
                f"Failed to get response, {method=}, {path=}, msg={res.text}"
            )
        return res.json()

    def get_cvrf(self, cvrf: str) -> CVRF:
        """
        Get detailed Microsoft security udpates, formatted according to the Common Vulnerabillity Reporting Framewaork.

        Args:
            cvrf (str): cvrf id (yyyy-mmm)
        Return:
            CVRF
        """
        res: Dict = self.request("GET", f"cvrf/{cvrf}")
        return CVRF(raw=res)

    def get_cvrfs(self, query: Optional[str] = None) -> List[Dict]:
        """
        Get a list of Microsoft security updates
        """
        path = f"Updates('{query}')" if query else "updates"
        logger.debug(f"{path=}")
        res: Dict[str, Any] = self.request("GET", path)
        cvrfs = res.get("value", [])
        return cvrfs

    def get_updates(
        self,
        update_id: Optional[str] = None,
        vul_id: Optional[str] = None,
        year: Optional[str] = None,
    ) -> List[CVRF]:
        """
        Get a list of Microsoft security updates
        """
        query = update_id or vul_id or year or None
        cvrfs = self.get_cvrfs(query)

        if vul_id:
            cvrf: CVRF = self.get_cvrf(cvrfs[0]["ID"])
            return cvrf.get_cve(vul_id)
        return [self.get_cvrf(cvrf["ID"]) for cvrf in cvrfs]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--version", action="version", version=__version__)
    parser.add_argument(
        "search", help="CVE ex) CVE-2017-0144, CVRF ex) 2020-Sep, KB ex) KB5014699"
    )
    options = parser.parse_args()
    msrc_client = MSRC()

    search = options.search
    if search.upper().startswith("CVE"):
        cve = msrc_client.get_updates(vul_id=search)
        print(cve)
        for remediation in cve.remediations:
            if remediation.type == 5:
                print(remediation.kb, remediation.url)
    elif search.upper().startswith("KB"):
        cvrfs = msrc_client.get_cvrfs()
        for cvrf in cvrfs:
            cvrf = msrc_client.get_cvrf(cvrf["ID"])
            for vuln in cvrf.vulnerabilites:
                for remediation in vuln.remediations:
                    if remediation.kb == search.upper():
                        print(f"{remediation.kb}: {remediation.url}")
                        return
    elif re.match(r"\d{4}\-\w{3}", search):
        cvrf = msrc_client.get_cvrf(search)
        for vuln in cvrf.vulnerabilites:
            print(f"{vuln.cve} {vuln.title}")
    else:
        raise SystemExit(f"CVE should start with CVE- or yyyy-m format, {search}")


if __name__ == "__main__":
    main()
