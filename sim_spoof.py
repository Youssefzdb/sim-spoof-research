#!/usr/bin/env python3
"""
SIM Spoof Research - SS7 & Telecom Security Research Toolkit
Author: Youssef Zeidi | Red Team Specialist
For authorized telecom security research and red team simulations only.
"""

import argparse, socket, struct, json, re, os
from datetime import datetime

BANNER = """
 ███████╗██╗███╗   ███╗    ███████╗██████╗  ██████╗  ██████╗ ███████╗
 ██╔════╝██║████╗ ████║    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝
 ███████╗██║██╔████╔██║    ███████╗██████╔╝██║   ██║██║   ██║█████╗
 ╚════██║██║██║╚██╔╝██║    ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝
 ███████║██║██║ ╚═╝ ██║    ███████║██║     ╚██████╔╝╚██████╔╝██║
 ╚══════╝╚═╝╚═╝     ╚═╝    ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝
        SS7 / Telecom Security Research v1.0 | Shadow Core
"""

# ─── SS7 Protocol Analysis ────────────────────────────────────────────
SS7_OPCODES = {
    0x23: "SendRoutingInfo (SRI)",
    0x45: "ProvideSubscriberInfo (PSI)",
    0x47: "AnyTimeInterrogation (ATI)",
    0x48: "AnyTimeSubscriptionInterrogation",
    0x3B: "InsertSubscriberData (ISD)",
    0x1C: "UpdateLocation (UL)",
    0x05: "SendAuthenticationInfo (SAI)",
}

def parse_ss7_opcode(opcode: int) -> str:
    return SS7_OPCODES.get(opcode, f"Unknown opcode 0x{opcode:02X}")

def analyze_ss7_vulnerabilities() -> dict:
    vulns = {
        "SRI_Abuse": {
            "severity": "HIGH",
            "description": "SendRoutingInfo allows MSISDN-to-IMSI mapping without authentication",
            "impact": "Subscriber location tracking, call interception setup",
            "mitigation": "Deploy SS7 firewall, block SRI from untrusted nodes",
            "cve": "CVE-2018-15967",
        },
        "ATI_Exposure": {
            "severity": "HIGH",
            "description": "AnyTimeInterrogation reveals real-time subscriber location to any HLR",
            "impact": "Real-time location tracking of any subscriber",
            "mitigation": "Filter ATI messages at SIGTRAN border",
            "cve": "N/A (protocol design flaw)",
        },
        "IMSI_Catching": {
            "severity": "CRITICAL",
            "description": "Fake BTS (IMSI catcher) can force 2G downgrade and capture IMSI",
            "impact": "Identity disclosure, call/SMS interception",
            "mitigation": "Enforce LTE-only mode, deploy IMSI catcher detectors",
            "cve": "N/A",
        },
        "SMS_Spoofing": {
            "severity": "MEDIUM",
            "description": "SMS originating address (OA) field is not authenticated in SS7",
            "impact": "SMS spoofing from any MSISDN",
            "mitigation": "SMS home routing, A2P sender validation",
            "cve": "N/A",
        },
        "SilentSMS": {
            "severity": "HIGH",
            "description": "Type-0 SMS (silent) can be used to ping subscriber location",
            "impact": "Covert location tracking",
            "mitigation": "Block Type-0 SMS at SMSC",
            "cve": "N/A",
        },
    }
    return vulns

# ─── MSISDN / IMSI Analysis ──────────────────────────────────────────
def analyze_msisdn(number: str) -> dict:
    number = re.sub(r"[^0-9+]", "", number)
    if number.startswith("+"):
        number = number[1:]

    # Country code lookup (simplified)
    CC_MAP = {
        "1": "USA/Canada", "44": "UK", "33": "France", "49": "Germany",
        "216": "Tunisia", "212": "Morocco", "213": "Algeria", "20": "Egypt",
        "966": "Saudi Arabia", "971": "UAE", "972": "Israel", "86": "China",
        "91": "India", "7": "Russia",
    }

    cc = None
    for code in sorted(CC_MAP.keys(), key=len, reverse=True):
        if number.startswith(code):
            cc = code
            break

    result = {
        "msisdn": "+" + number,
        "country_code": cc,
        "country": CC_MAP.get(cc, "Unknown"),
        "national_number": number[len(cc):] if cc else number,
        "length_valid": len(number) in range(7, 16),
        "type": "Mobile" if len(number) >= 10 else "Short/Service",
    }
    return result

def imsi_to_mcc_mnc(imsi: str) -> dict:
    imsi = re.sub(r"[^0-9]", "", imsi)
    if len(imsi) < 6:
        return {"error": "IMSI too short"}
    mcc = imsi[:3]
    mnc = imsi[3:5]
    msin = imsi[5:]
    MCC_MAP = {"208": "France", "234": "UK", "310": "USA", "404": "India",
               "460": "China", "605": "Tunisia", "604": "Morocco", "603": "Algeria"}
    return {"imsi": imsi, "mcc": mcc, "country": MCC_MAP.get(mcc, "Unknown"),
            "mnc": mnc, "msin": msin, "length": len(imsi)}

# ─── Network Telecom Scan ─────────────────────────────────────────────
def scan_sigtran_ports(host: str) -> dict:
    SIGTRAN_PORTS = {
        2905: "M3UA (SS7 over IP)",
        2904: "M2UA",
        9900: "SCCP User Adaptation",
        3868: "Diameter (4G/LTE)",
        5060: "SIP",
        5061: "SIP-TLS",
    }
    results = {}
    for port, desc in SIGTRAN_PORTS.items():
        try:
            s = socket.socket()
            s.settimeout(1)
            open_ = s.connect_ex((host, port)) == 0
            s.close()
            results[port] = {"desc": desc, "status": "OPEN" if open_ else "CLOSED"}
            if open_:
                print(f"  [OPEN] {port}/tcp - {desc}")
        except:
            results[port] = {"desc": desc, "status": "ERROR"}
    return results

# ─── Report Generator ─────────────────────────────────────────────────
def generate_report(findings: dict, output: str):
    report = {
        "title": "SS7 / Telecom Security Assessment",
        "generated": datetime.now().isoformat(),
        "author": "Youssef Zeidi | Shadow Core Red Team",
        "findings": findings,
    }
    with open(output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report: {output}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="SIM Spoof Research Toolkit")
    parser.add_argument("--module", choices=["ss7","msisdn","imsi","scan","all"], required=True)
    parser.add_argument("--number", help="MSISDN to analyze (e.g. +21694340389)")
    parser.add_argument("--imsi", help="IMSI to decode")
    parser.add_argument("--target", help="Host to scan for SIGTRAN ports")
    parser.add_argument("--output", default="telecom_report.json")
    args = parser.parse_args()

    findings = {}

    if args.module in ("ss7", "all"):
        print("[*] SS7 Vulnerability Analysis:")
        vulns = analyze_ss7_vulnerabilities()
        for name, v in vulns.items():
            sev = v["severity"]
            icon = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡"
            print(f"  {icon} [{sev}] {name}")
            print(f"      {v['description']}")
        findings["ss7_vulnerabilities"] = vulns

    if args.module in ("msisdn", "all") and args.number:
        print(f"\n[*] MSISDN Analysis: {args.number}")
        result = analyze_msisdn(args.number)
        for k, v in result.items():
            print(f"  {k}: {v}")
        findings["msisdn"] = result

    if args.module in ("imsi", "all") and args.imsi:
        print(f"\n[*] IMSI Decode: {args.imsi}")
        result = imsi_to_mcc_mnc(args.imsi)
        for k, v in result.items():
            print(f"  {k}: {v}")
        findings["imsi"] = result

    if args.module in ("scan", "all") and args.target:
        print(f"\n[*] SIGTRAN Port Scan: {args.target}")
        results = scan_sigtran_ports(args.target)
        open_ports = [p for p, v in results.items() if v["status"] == "OPEN"]
        print(f"[+] Open SIGTRAN ports: {open_ports}")
        findings["port_scan"] = results

    generate_report(findings, args.output)

if __name__ == "__main__":
    main()
