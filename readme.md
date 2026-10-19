# Python Security Log Analyser

## Overview
A beginner Python project that analyses sample authentication logs to count successful and failed login attempts and identify IP addresses with repeated failed logins.

## Features
- Reads authentication logs from a text file.
- Counts successful and failed login attempts.
- Groups login attempts by IP address.
- Flags IP addresses with two or more failed login attempts.
- Displays a summary of login activity.

## Technologies
- Python
- Git
- GitHub
- Visual Studio Code

## How to Run
1. Clone or download this repository.
2. Make sure Python is installed.
3. Open a terminal in the project directory.
4. Run:

   `python analyser.py`

## Example Alert
`SECURITY ALERT: 192.168.1.50 has 2 failed login attempts`

## What I Learned
Through this project, I practised Python file handling, loops, conditional statements, dictionaries, string manipulation, counting data and basic security log analysis. I also learned how to track changes using Git and publish a project on GitHub.

## Future Improvements
- Add automated tests.
- Improve handling of malformed log entries.
- Make the alert threshold configurable.
- Improve the output and reporting.

## Disclaimer
This project uses sample log data for educational purposes. It is not a production security monitoring system.