import os

def analyze_logs(log_file_path):
    print(f"=== Starting Scan on: {log_file_path} ===")
    
    # Check if the file actually exists before trying to open it
    if not os.path.exists(log_file_path):
        print("Error: Log file not found!")
        return

    failed_attempts_count = 0
    unique_attacker_ips = set()
    targeted_users = {}

    # Open and process the file line-by-line (highly memory efficient)
    with open(log_file_path, 'r') as file:
        for line in file:
            # Check for our security keyword
            if "Failed password" in line:
                failed_attempts_count += 1
                words = line.split()
                
                # Extracting specific data points based on line structure
                # Handling variation if line has 'invalid user' string
                if "invalid user" in line:
                    username = words[words.index("user") + 1]
                else:
                    username = words[words.index("for") + 1]
                    
                ip_address = words[words.index("from") + 1]
                
                # Track the statistics
                unique_attacker_ips.add(ip_address)
                targeted_users[username] = targeted_users.get(username, 0) + 1
                
                # Print individual alerts out instantly
                timestamp = " ".join(words[0:3])
                print(f"[ALERT] Failed login detected at {timestamp} | User: '{username}' | IP: {ip_address}")

    # Display the final security summary report
    print("\n" + "="*40)
    print("           SECURITY REPORT            ")
    print("="*40)
    print(f"Total Failed Login Attempts: {failed_attempts_count}")
    print(f"Unique Malicious IPs Detected: {len(unique_attacker_ips)}")
    print(f"List of Attacking IPs: {', '.join(unique_attacker_ips)}")
    print("\nTargeted Accounts Breakdown:")
    for user, count in targeted_users.items():
        print(f" - Account '{user}': tried {count} times")
    print("="*40)

# Run the analyzer on our mock log file
analyze_logs("data/mock_auth.log")
