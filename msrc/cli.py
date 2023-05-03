import re
import argparse

from .api import MSRC
from msrc import __version__


def main():
    parser = argparse.ArgumentParser(prog="msrc")
    parser.add_argument(
        "-v", "--version", action="version", version=__version__
    )
    parser.add_argument(
        "search",
        help="CVE ex) CVE-2017-0144, CVRF ex) 2020-Sep, KB ex) KB5014699"
    )

    options = parser.parse_args()
    search = options.search
    msrc_client = MSRC()

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
        for vuln in cvrf.Vulnerability:
            print(
                f"{vuln.CVE:<15} {vuln.Title:<30} "
                f"{[score.BaseScore for score in vuln.CVSSScoreSets]}")
    else:
        raise SystemExit(
            f"CVE should start with CVE- or yyyy-m format, {search}"
        )


if __name__ == "__main__":
    main()