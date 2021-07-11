# coding: utf-8
import json
import msrc
sample = json.load(open('sample.json'))
cvrf = msrc.CVRF(sample)
cvrf.products
cvrf.vulnerabilites
