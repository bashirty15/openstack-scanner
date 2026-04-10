import json
import datetime


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def generate_report(findings, score):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "=" * 50)
    print("   OpenStack Security Scanner — Report")
    print(f"   Generated: {timestamp}")
    print("=" * 50)

    if not findings:
        print("\n✅ No security issues detected.\n")
    else:
        # Sort by severity
        sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 9))

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in sorted_findings:
            counts[f.get("severity", "LOW")] += 1

        print(f"\n📋 Found {len(findings)} issue(s):")
        for sev, count in counts.items():
            if count:
                print(f"   {sev}: {count}")

        print("\n" + "-" * 50)

        for f in sorted_findings:
            sev = f.get("severity", "?")
            print(f"\n[{sev}] {f.get('check', 'Unknown Check')}")
            print(f"  Resource    : {f.get('resource', 'N/A')}")
            print(f"  Detail      : {f.get('detail', 'N/A')}")
            print(f"  Remediation : {f.get('remediation', 'N/A')}")

    print("\n" + "-" * 50)
    print(f"Overall Risk Score: {score}/100")

    if score >= 70:
        print("🔴 Cloud Security Status: HIGH RISK")
    elif score >= 40:
        print("🟡 Cloud Security Status: MEDIUM RISK")
    else:
        print("🟢 Cloud Security Status: LOW RISK")

    print("=" * 50 + "\n")

    # Export to JSON
    report_data = {
        "generated_at": timestamp,
        "risk_score": score,
        "total_findings": len(findings),
        "findings": findings,
    }

    output_file = f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(report_data, f, indent=2)

    print(f"📄 JSON report saved to: {output_file}\n")
