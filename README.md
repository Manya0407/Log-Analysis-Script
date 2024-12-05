# Log Analysis Script

This project is a Python script that processes server log files to extract key information, such as:
1.Request counts per IP address
2.The most frequently accessed endpoint
3.Detection of suspicious activity, such as brute force login attempts

# The script is intended for log analysis tasks, commonly used in cybersecurity for detecting potential threats and analyzing server traffic.
# Requirements
1.Python 3.x
2.Pandas (for data handling)
3.Git (optional, for version control)


# Notes:
The script uses a threshold (default 4) to detect suspicious activity based on failed login attempts. This can be adjusted in the script if needed.
