# Proxmox VDI Portal for CCSE UITS

This project is a Flask-based web portal that allows users to access virtual machines hosted on a Proxmox Virtual Environment (PVE). Built as part of the CS 4850 Senior Capstone at Kennesaw State University, the system enables LDAP-authenticated users to log in, view their assigned VMs, and access them via console through the web.

## Features

- LDAP and PAM authentication support
- Secure login and session handling (CSRF, Secure cookies)
- Filtered VM access based on user groups
- Launch noVNC console sessions
- HTTPS/TLS support

## Project Structure

- `app.py`: Main Flask application logic including routes, authentication, and API interaction.
- `login.html`, `dashboard.html`, `dashboard2.html`: Frontend templates rendered based on user actions.
- `config.py`: Configuration file for environment-specific variables (explained below).

## Requirements

- Python 3.8+
- Flask
- Proxmox VE 8.2+
- A running Proxmox server accessible from the Flask app
- LDAP server (slapd or Active Directory)


##Setup
1. Clone the repo
2. pip instal flask requests
3. config.py setup

**Create a `config.py` File**

You must create a `config.py` file in the root directory to define environment-specific settings used throughout the app.

Example `config.py`:
```python
PVE_NODE = "pve"
PROXMOX_INTERNAL_IP = "192.168.2.2"  # Internal IP of your Proxmox server
PROXMOX_PUBLIC_IP = "100.222.2.22"     # Public IP shown in noVNC console URLs
