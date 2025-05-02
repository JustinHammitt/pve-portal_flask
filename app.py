from flask import Flask, request, render_template, session, redirect, make_response
import requests
import urllib3
import os
import re
from config import PVE_NODE, PROXMOX_INTERNAL_IP, PROXMOX_PUBLIC_IP

# Suppress SSL warnings (for self-signed certs)
urllib3.disable_warnings()

# === Flask App Setup ===
app = Flask(__name__)
app.secret_key = os.urandom(24)

IS_PRODUCTION = os.getenv("FLASK_ENV") == "production"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    SESSION_COOKIE_SAMESITE='Lax'
)




# Internal IP that Flask uses to talk to Proxmox API
PVE_API = f"https://{PROXMOX_INTERNAL_IP}:8006/api2/json/"

# === Helpers ===

def authenticate_user(username, password, proxmox_host):
    url = f"https://{proxmox_host}:8006/api2/json/access/ticket"
    data = {
        "username": username,
        "password": password
    }
    try:
        response = requests.post(url, data=data, verify=False)
        response.raise_for_status()
        ticket_data = response.json()
        return ticket_data['data']
    except requests.exceptions.RequestException as e:
        print(f"Authentication failed: {e}")
        return None


def generate_novnc_url(vm_id, node_name, ticket, csrf_token, proxmox_url, public_ip):
    try:
        headers = {
            "Cookie": f"PVEAuthCookie={ticket}",
            "CSRFPreventionToken": csrf_token
        }

        url = f"{proxmox_url}nodes/{node_name}/qemu/{vm_id}/vncproxy"
        response = requests.post(url, headers=headers, verify=False)
        response.raise_for_status()

        data = response.json()['data']
        vncticket = data['ticket']
        vmname = f"vm{vm_id}"
        return (
            f"https://{public_ip}:8006/?console=kvm"
            f"&novnc=1&vmid={vm_id}&vmname={vmname}"
            f"&node={node_name}&resize=scale&cmd=start&password={vncticket}"
        )

    except requests.exceptions.RequestException as e:
        print(f"Failed to generate noVNC URL: {e}")
        return None



def get_all_vm_ids(headers, proxmox_url):
    try:
        response = requests.get(f"{proxmox_url}nodes/{PVE_NODE}/qemu", headers=headers, verify=False)
        response.raise_for_status()
        data = response.json()
        return [item['vmid'] for item in data['data'] if 'vmid' in item]
    except requests.exceptions.RequestException as e:
        print(f"Failed to get VM IDs: {e}")
        return []


# === Routes ===

@app.before_request
def redirect_http_to_https_in_prod():
    if IS_PRODUCTION and request.url.startswith("http://"):
        return redirect(request.url.replace("http://", "https://", 1))


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        realm = "LDAP"
        if "@pam" in username.lower():
            realm = "pam"
        clean_user = username.split("@")[0]
        user_id = f"{clean_user}@{realm}"

        ticket_data = authenticate_user(user_id, password, PROXMOX_INTERNAL_IP)

        if ticket_data:
            session["ticket"] = ticket_data["ticket"]
            session["csrf"] = ticket_data["CSRFPreventionToken"]
            session["cookie"] = f"PVEAuthCookie={ticket_data['ticket']}"
            session["user"] = user_id
            return redirect("/dashboard")

        return "Invalid credentials", 403

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "ticket" not in session:
        return redirect("/")

    headers = {
        "Cookie": f"PVEAuthCookie={session['ticket']}",
        "CSRFPreventionToken": session["csrf"]
    }

    try:
        resp = requests.get(f"{PVE_API}/nodes/{PVE_NODE}/qemu", headers=headers, verify=False)
        if resp.status_code != 200:
            return f"Failed to get VM list: {resp.status_code} - {resp.text}", 500

        vms = resp.json()["data"]
        filtered_vms = [vm for vm in vms if not vm.get("template")]
        return render_template("dashboard.html", vms=filtered_vms, node=PVE_NODE, csrf_token=session["csrf"])

    except Exception as e:
        return f"Dashboard error: {str(e)}", 500


@app.route("/get_console_url/<vmid>/<vmname>", methods=["POST"])
def get_console_url(vmid, vmname):
    if "ticket" not in session or "csrf" not in session:
        return redirect("/")
    url = generate_novnc_url(
        vm_id=vmid,
        node_name=PVE_NODE,
        ticket=session["ticket"],
        csrf_token=session["csrf"],
        proxmox_url=PVE_API,
        public_ip=PROXMOX_PUBLIC_IP
    )


    if not url:
        return "Failed to generate console URL", 500

    return f"""
    <h2>Copy and paste this full console URL into your browser:</h2>
    <textarea style='width:100%;height:80px'>{url}</textarea><br>
    <a href="{url}" target="_blank">Launch Console</a><br>
    <a href="/dashboard">Back to Dashboard</a>
    """


@app.route("/shutdown/<vmid>", methods=["POST"])
def shutdown_vm(vmid):
    if "ticket" not in session:
        return redirect("/")
    headers = {
        "Cookie": session["cookie"],
        "CSRFPreventionToken": session["csrf"]
    }
    url = f"https://{PROXMOX_INTERNAL_IP}:8006/api2/json/nodes/{PVE_NODE}/qemu/{vmid}/status/shutdown"
    try:
        requests.post(url, headers=headers, verify=False).raise_for_status()
    except Exception as e:
        app.logger.error(f"shutdown failed for vm {vmid}: {e}")
    return redirect("/dashboard")

@app.route("/reboot/<vmid>", methods=["POST"])
def reboot_vm(vmid):
    if "ticket" not in session:
        return redirect("/")
    headers = {
        "Cookie": session["cookie"],
        "CSRFPreventionToken": session["csrf"]
    }
    url = f"https://{PROXMOX_INTERNAL_IP}:8006/api2/json/nodes/{PVE_NODE}/qemu/{vmid}/status/reboot"
    try:
        requests.post(url, headers=headers, verify=False).raise_for_status()
    except Exception as e:
        app.logger.error(f"reboot failed for vm {vmid}: {e}")
    return redirect("/dashboard")

@app.route("/poweron/<vmid>", methods=["POST"])
def poweron_vm(vmid):
    if "ticket" not in session:
        return redirect("/")
    headers = {
        "Cookie": session["cookie"],
        "CSRFPreventionToken": session["csrf"]
    }
    url = f"https://{PROXMOX_INTERNAL_IP}:8006/api2/json/nodes/{PVE_NODE}/qemu/{vmid}/status/start"
    try:
        requests.post(url, headers=headers, verify=False).raise_for_status()
    except Exception as e:
        app.logger.error(f"poweron failed for vm {vmid}: {e}")
    return redirect("/dashboard")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# === Run App ===
if __name__ == "__main__":

    #self signed SSL certs for HTTPS secure connection
    context = (
        "portal.pem",
        "portal.key"
    )
    app.run(host="0.0.0.0", port=5000, debug=True, ssl_context=context)
