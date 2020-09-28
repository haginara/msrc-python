import pytest
import unittest
from unittest import mock

import msrc

def test_msrc_version(capsys):
    with mock.patch('sys.argv', ['msrc', '-v']):
        with pytest.raises(SystemExit):
            msrc.main()
        out, _ = capsys.readouterr()
    
    assert(out.strip() == msrc.__version__)


def test_msrc_csv(capsys):
    with mock.patch('sys.argv', ['msrc', 'CVE-2017-0144']):
        msrc.main()
        out, _ = capsys.readouterr()
    
    expected_out = [
        "Matched CVRF: 2017-Mar",
        "KB4012216",
        "KB4013198",
        "KB4012214",
        "KB4012598",
        "KB4012212",
        "KB4013429",
        "KB4012215",
        "KB4012606",
        "KB4012213",
        "KB4012217"
    ]
    for item in expected_out:
        assert(item in out)
    
def test_msrc_cvrf(capsys):
    with mock.patch('sys.argv', ['msrc', '2017-Mar']):
        msrc.main()
        out, _ = capsys.readouterr()
    
    expected_out = [
        "CVE-2017-0005 Windows GDI Elevation of Privilege Vulnerability",
        "CVE-2017-0006 Microsoft Office Memory Corruption Vulnerability",
        "CVE-2017-0024 Win32k Elevation of Privilege Vulnerability",
        "CVE-2017-0025 Windows GDI Elevation of Privilege Vulnerability",
        "CVE-2017-0026 Win32k Elevation of Privilege Vulnerability",
        "CVE-2017-0032 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0033 Microsoft Browser Spoofing Vulnerability",
        "CVE-2017-0034 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0035 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0037 Microsoft Browser Memory Corruption Vulnerability",
        "CVE-2017-0038 Windows GDI Information Disclosure Vulnerability",
        "CVE-2017-0039 Windows DLL Loading Remote Code Execution Vulnerability",
        "CVE-2017-0040 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0042 Windows DirectShow Information Disclosure Vulnerability",
        "CVE-2017-0043 Microsoft Active Directory Federation Services Information Disclosure",
        "CVE-2017-0045 Windows DVD Maker Cross-Site Request Forgery Vulnerability",
        "CVE-2017-0047 Windows GDI Elevation of Privilege Vulnerability",
        "CVE-2017-0051 Hyper-V Denial of Service Vulnerability",
        "CVE-2017-0052 Microsoft Office Memory Corruption Vulnerability",
        "CVE-2017-0053 Microsoft Office Memory Corruption Vulnerability",
        "CVE-2017-0055 Microsoft IIS Server XSS Elevation of Privilege Vulnerability",
        "CVE-2017-0105 Microsoft Office Information Disclosure Vulnerability",
        "CVE-2017-0108 Windows Graphics Component Remote Code Execution Vulnerability",
        "CVE-2017-0111 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0112 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0113 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0114 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0115 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0116 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0117 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0118 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0119 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0120 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0121 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0122 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0123 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0124 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0125 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0126 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0127 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0128 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0143 Windows SMB Remote Code Execution Vulnerability",
        "CVE-2017-0144 Windows SMB Remote Code Execution Vulnerability",
        "CVE-2017-0145 Windows SMB Remote Code Execution Vulnerability",
        "CVE-2017-0146 Windows SMB Remote Code Execution Vulnerability",
        "CVE-2017-0147 Windows SMB Information Disclosure Vulnerability",
        "CVE-2017-0148 Windows SMB Remote Code Execution Vulnerability",
        "CVE-2017-0129 Microsoft Lync for Mac Certificate Validation Vulnerability",
        "CVE-2017-0007 Device Guard Security Feature Bypass Vulnerability",
        "CVE-2017-0008 Microsoft Browser Information Disclosure Vulnerability",
        "CVE-2017-0009 Microsoft Browser Information Disclosure Vulnerability",
        "CVE-2017-0010 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0011 Microsoft Browser Information Disclosure Vulnerability",
        "CVE-2017-0012 Microsoft Browser Spoofing Vulnerability",
        "CVE-2017-0014 Windows Graphics Component Remote Code Execution Vulnerability",
        "CVE-2017-0015 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0016 Windows Denial of Service Vulnerability",
        "CVE-2017-0017 Microsoft Browser Information Disclosure Vulnerability",
        "CVE-2017-0018 Microsoft Browser Memory Corruption Vulnerability",
        "CVE-2017-0019 Microsoft Office Memory Corruption Vulnerability",
        "CVE-2017-0020 Microsoft Office Memory Corruption Vulnerability",
        "CVE-2017-0021 Hyper-V vSMB Remote Code Execution Vulnerability",
        "CVE-2017-0022 Microsoft XML Core Services Information Disclosure Vulnerability",
        "CVE-2017-0023 Windows PDF Remote Code Execution Vulnerability",
        "CVE-2017-0027 Microsoft Excel Information Disclosure Vulnerability",
        "CVE-2017-0029 Microsoft Office Denial of Service Vulnerability",
        "CVE-2017-0030 Microsoft Office Memory Corruption Vulnerability",
        "CVE-2017-0031 Microsoft Office Memory Corruption Vulnerability",
        "CVE-2017-0049 Internet Explorer Information Disclosure Vulnerability",
        "CVE-2017-0050 Windows Elevation of Privilege Vulnerability",
        "CVE-2017-0056 Windows Kernel Elevation of Privilege Vulnerability",
        "CVE-2017-0057 Windows DNS Query Information Disclosure Vulnerability",
        "CVE-2017-0059 Microsoft Browser Information Disclosure Vulnerability",
        "CVE-2017-0060 Windows GDI Information Disclosure Vulnerability",
        "CVE-2017-0061 None",
        "CVE-2017-0062 Windows GDI Information Disclosure Vulnerability",
        "CVE-2017-0063 None",
        "CVE-2017-0065 Microsoft Browser Information Disclosure Vulnerability",
        "CVE-2017-0066 Microsoft Edge Security Feature Bypass Vulnerability",
        "CVE-2017-0067 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0068 Microsoft Edge based on Edge HTML Information Disclosure Vulnerability",
        "CVE-2017-0069 Microsoft Browser Spoofing Vulnerability",
        "CVE-2017-0070 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0071 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0072 Windows Uniscribe Remote Code Execution Vulnerability",
        "CVE-2017-0073 Windows GDI Information Disclosure Vulnerability",
        "CVE-2017-0074 Hyper-V Denial of Service Vulnerability",
        "CVE-2017-0075 Windows Hyper-V Remote Code Execution Vulnerability",
        "CVE-2017-0076 Hyper-V Denial of Service Vulnerability",
        "CVE-2017-0078 Win32k Elevation of Privilege Vulnerability",
        "CVE-2017-0079 Win32k Elevation of Privilege Vulnerability",
        "CVE-2017-0080 Win32k Elevation of Privilege Vulnerability",
        "CVE-2017-0081 Win32k Elevation of Privilege Vulnerability",
        "CVE-2017-0082 Win32k Elevation of Privilege Vulnerability",
        "CVE-2017-0083 Windows Uniscribe Remote Code Execution Vulnerability",
        "CVE-2017-0084 Windows Uniscribe Remote Code Execution Vulnerability",
        "CVE-2017-0085 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0086 Windows Uniscribe Remote Code Execution Vulnerability",
        "CVE-2017-0087 Windows Uniscribe Remote Code Execution Vulnerability",
        "CVE-2017-0088 Windows Uniscribe Remote Code Execution Vulnerability",
        "CVE-2017-0089 Windows Uniscribe Remote Code Execution Vulnerability",
        "CVE-2017-0090 Windows Uniscribe Remote Code Execution Vulnerability",
        "CVE-2017-0091 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0092 Windows Uniscribe Information Disclosure Vulnerability",
        "CVE-2017-0094 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0104 iSNS Server Memory Corruption Vulnerability",
        "CVE-2017-0103 Windows Registry Elevation of Privilege Vulnerability",
        "CVE-2017-0102 Windows Elevation of Privilege Vulnerability",
        "CVE-2017-0101 Windows Transaction Manager Elevation of Privilege Vulnerability",
        "CVE-2017-0100 Windows COM Session Elevation of Privilege Vulnerability",
        "CVE-2017-0099 Hyper-V Denial of Service Vulnerability",
        "CVE-2017-0098 Hyper-V Denial of Service Vulnerability",
        "CVE-2017-0097 Hyper-V Denial of Service Vulnerability",
        "CVE-2017-0096 Windows Hyper-V Information Disclosure Vulnerability",
        "CVE-2017-0095 Hyper-V vSMB Remote Code Execution Vulnerability",
        "CVE-2017-0109 Windows Hyper-V Remote Code Execution Vulnerability",
        "CVE-2017-0110 Microsoft Exchange Server Elevation of Privilege Vulnerability",
        "CVE-2017-0130 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0131 Scripting Engine Information Disclosure Vulnerability",
        "CVE-2017-0132 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0133 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0134 Microsoft Edge Memory Corruption Vulnerability",
        "CVE-2017-0135 Microsoft Edge Security Feature Bypass Vulnerability",
        "CVE-2017-0136 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0137 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0138 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0140 Microsoft Edge Security Feature Bypass Vulnerability",
        "CVE-2017-0141 Scripting Engine Memory Corruption Vulnerability",
        "ADV170003 March 2017 Adobe Flash Security Update",
        "CVE-2017-0149 Microsoft Browser Memory Corruption Vulnerability",
        "CVE-2017-0150 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0151 Scripting Engine Memory Corruption Vulnerability",
        "CVE-2017-0154 Internet Explorer Elevation of Privilege Vulnerability",
        "CVE-2017-0001 Windows GDI Elevation of Privilege Vulnerability",
        "CVE-2017-0107 Microsoft SharePoint Elevation of Privilege Vulnerability",
    ]
    for item in expected_out:
        assert(item in out)