from typing import Optional, Any, Dict, List
import logging
import requests

from .object import CVRF

logger = logging.getLogger(__name__)


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
        return CVRF(data=res)

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
