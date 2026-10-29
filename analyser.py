from datetime import datetime

def should_flag_ip(value):
    return value >= 2

def get_severity_level(value):
    if value >= 6:
        return "CRITICAL"
    elif value >= 4:
        return "HIGH"
    elif value >= 3:
        return "MEDIUM"
    elif value >= 2:
        return "LOW"
    else:
        return None


def analyse_log(filename, report_filename="security_alerts.txt"):
    search = "ip="
    SUCCESS = 0
    FAILED = 0
    flagged_ips = 0
    security_alerts = []
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0


    try:
        with open(filename, "r") as f:
            print("SEARCHING FOR SUCCESS AND FAILED LOGIN ATTEMPTS")

            FAILED_ip = {}
            SUCCESS_ip = {}

            for line in f:
                if "ip=" not in line:
                    continue

                current_ip = line.split(search)[1].strip()

                if not current_ip:
                    continue

                if "SUCCESS" in line:
                    SUCCESS_ip[current_ip] = SUCCESS_ip.get(current_ip, 0) + 1
                    SUCCESS += 1

                elif "FAILED" in line:
                    FAILED_ip[current_ip] = FAILED_ip.get(current_ip, 0) + 1
                    FAILED += 1

            sorted_failed_ips = sorted(
                FAILED_ip.items(),
                key=lambda x: x[1],
                reverse=True
            )

            for key, value in sorted_failed_ips:
                if should_flag_ip(value):
                    flagged_ips += 1

                severity = get_severity_level(value)
                if severity is not None:
                    print(f"SECURITY ALERT: {key} has {value} [{severity}]")
                    security_alerts.append((key, value, severity))
                    if severity == "CRITICAL":
                        critical_count += 1
                    elif severity == "HIGH":
                        high_count += 1
                    elif severity == "MEDIUM":
                        medium_count += 1
                    elif severity == "LOW":
                        low_count += 1


            print("UNIQUE IPs FLAGGED:", flagged_ips)
            with open("security_alerts.txt", "w") as report:
                report.write("SECURITY ALERTS REPORT\n")
                report.write("======================\n")
                report.write(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                report.write("\n")
                report.write("SUMMARY\n")
                report.write("-------\n")
                report.write(f"Total alerts: {len(security_alerts)}\n")
                report.write(f"CRITICAL: {critical_count}\n")
                report.write(f"HIGH: {high_count}\n")
                report.write(f"MEDIUM: {medium_count}\n")
                report.write(f"LOW: {low_count}\n")
                report.write("\n")
                report.write("SECURITY ALERTS\n")
                report.write("---------------\n")

                for alert in security_alerts:
                    report.write(f"{alert[0]} has {alert[1]} failed attempts and the severity is [{alert[2]}]\n")

    except FileNotFoundError:
        print("File not found. Please check the file path and try again.")
    else:

      print("TOTAL SUCCESSFUL LOGIN ATTEMPTS:", SUCCESS)
      print("TOTAL FAILED LOGIN ATTEMPTS:", FAILED)
      print("TOTAL LOGIN ATTEMPTS:", SUCCESS + FAILED)

if __name__ == "__main__":
    analyse_log("logs/sample.log")