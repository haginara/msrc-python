# coding: utf-8
import json
import msrc
import os


def test_msrc_cve():
    sample_path = os.path.join(
        os.path.dirname(__file__),
        'sample.json'
    )
    sample = json.load(open(sample_path))
    cvrf = msrc.CVRF(raw=sample)
    assert isinstance(cvrf, msrc.CVRF)
    assert cvrf.title == "July 1, 2021 CVE Release"
    assert isinstance(cvrf.vulnerabilites, msrc.Vulnerability)


def test_msrc_search_cve():
    msrc_client = msrc.MSRC()
    cve = msrc_client.get_updates(vul_id="CVE-2017-0144")
    assert isinstance(cve, msrc.Vulnerability)
