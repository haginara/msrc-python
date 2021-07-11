# coding: utf-8
import json
import msrc
import msrc

def test_msrc_cve():
    sample = json.load(open('sample.json'))
    cvrf = msrc.CVRF(sample)
    cvrf.products
    cvrf.vulnerabilites