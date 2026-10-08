filename = "logs/sample.log"
search = "ip="
with open(filename, "r") as f:
    print("SEARCHING FOR SUCCESS AND FAILED LOGIN ATTEMPTS")
    SUCCESS = 0
    FAILED = 0
    FAILED_ip = {}
    SUCCESS_ip = {}

    for line in f:
        if "SUCCESS" in line:
           current_ip =line.split(search)[1].strip()
           SUCCESS_ip[current_ip] = SUCCESS_ip.get(current_ip, 0) + 1
           SUCCESS += 1 
        elif "FAILED" in line:
            current_ip =line.split(search)[1].strip()
            FAILED_ip[current_ip] = FAILED_ip.get(current_ip, 0) + 1
            FAILED += 1
    for key, value in FAILED_ip.items():
        if value >= 2:
           print(f"SECURITY ALERT: {key} has {value} failed login attempts")  

    for key, value in SUCCESS_ip.items():
        if value >= 2:
           print(f"SECURITY ALERT: {key} has {value} successful login attempts")
print("TOTAL SUCCESSFUL LOGIN ATTEMPTS: ", SUCCESS)
print("TOTAL FAILED LOGIN ATTEMPTS: ", FAILED)
print("TOTAL LOGIN ATTEMPTS: ", (SUCCESS) + (FAILED))
