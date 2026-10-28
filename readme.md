# Python Security Log Analyser

## Overview

A Python-based security log analysis tool that processes authentication logs, counts successful and failed login attempts, and identifies IP addresses with repeated failed logins. It assigns severity levels to alerts based on the number of failed attempts.

## Features

- Reads authentication logs from a text file.
- Counts successful, failed, and total login attempts.
- Groups login attempts by IP address.
- Flags IP addresses with two or more failed login attempts.
- Assigns alert severity levels: LOW, MEDIUM, HIGH, and CRITICAL.
- Sorts failed-login results by frequency.
- Handles missing files and skips log entries without a valid IP address.
- Includes automated tests using pytest.

## Technologies

- Python
- pytest
- Git and GitHub
- Visual Studio Code

## How to Run

1. Install Python 3.
2. Clone or download this repository.
3. Open a terminal in the project directory.
4. Run the analyser:

   ```bash
   python analyser.py
   ```

The analyser uses the sample log file at `logs/sample.log`.

## Running the Tests

Install pytest if it is not already installed:

```bash
python -m pip install pytest
```

Run the test suite:

```bash
python -m pytest -v
```

The tests cover IP flagging, severity levels, missing files, valid log files, and empty log files.

## Example Alert

```text
SECURITY ALERT: 192.168.1.50 has 4 [HIGH]
SECURITY ALERT: 192.168.1.22 has 2 [LOW]
```

## What I Learned

Through this project, I practised Python file handling, loops, conditional statements, dictionaries, string manipulation, data aggregation, error handling, and basic security log analysis. I also gained experience writing automated tests with pytest and managing source code with Git.

## Future Improvements

- Export alerts to a report file.
- Make the alert threshold configurable.
- Add timestamps and additional log formats.
- Improve reporting and visualisation.

## Disclaimer

This project uses sample log data for educational purposes. It is not a production security monitoring system.
