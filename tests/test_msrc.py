# coding: utf-8
import json
from msrc import CVRF, Vulnerability
from msrc.api import MSRC
import os


def test_msrc_cve():
    sample_path = os.path.join(
        os.path.dirname(__file__),
        'sample.json'
    )
    sample = json.load(open(sample_path))
    cvrf = CVRF(data=sample)
    assert isinstance(cvrf, CVRF)
    assert cvrf.DocumentTitle == "July 1, 2021 CVE Release"
    assert isinstance(cvrf.Vulnerability[0], Vulnerability)


def test_msrc_search_cve():
    msrc_client = MSRC()
    cve = msrc_client.get_updates(vul_id="CVE-2017-0144")
    assert isinstance(cve, Vulnerability)
