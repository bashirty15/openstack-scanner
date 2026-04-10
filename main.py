from config import get_connection
from collector.data_collector import collect_data
from rules.network_rules import check_network_rules
from rules.ip_rules import check_ip_rules
from rules.storage_rules import check_storage_rules
from scoring.risk_scorer import calculate_score
from reporting.report_generator import generate_report


def main():
    print("\n🚀 Starting OpenStack Security Scanner...\n")

    conn = get_connection()
    data = collect_data(conn)

    findings = []
    findings += check_network_rules(data)
    findings += check_ip_rules(data)
    findings += check_storage_rules(data)

    score = calculate_score(findings)
    generate_report(findings, score)


if __name__ == "__main__":
    main()
