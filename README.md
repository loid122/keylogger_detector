# keylogger_detector

A Python-based keylogger detection tool that performs multiple checks to identify suspicious processes that may capture keystrokes or send data secretly.

# Features

Detect Known Keylogging Libraries: Scans for processes using common keylogging libraries.

Monitor Network Traffic: Analyzes outgoing traffic for suspicious data transmissions.

Check Long-Running Processes: Identifies processes that run unusually long.

Inspect Startup Entries: Detects unauthorized programs set to launch at system startup.

# Technologies Used

Language: Python

Libraries: psutil, scapy (for network monitoring), regex
