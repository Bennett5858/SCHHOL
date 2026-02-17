import subprocess
import os
import platform
import ctypes
import sys
import getpass
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

HTML_REPORT = "security_audit_report.html"
report_data = []

def log(text):
    report_data.append(text)

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True, errors="ignore")
    except Exception as e:
        return str(e)

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except:
        return False

def admin_privilege_check():
    print(Fore.CYAN + "\n[+] Checking current privilege level...\n")

    current_user = getpass.getuser()
    admin_state = is_admin()

    print(f"Current Logged-in User : {current_user}")
    log(f"<h3>Current User: {current_user}</h3>")

    if admin_state:
        print(Fore.GREEN + "Privilege Level       : ADMINISTRATOR ✔")
        log("<p style='color:green'>Running with Administrator privileges</p>")
    else:
        print(Fore.RED + "Privilege Level       : STANDARD USER ✖")
        log("<p style='color:red'>Running as Standard User</p>")

def check_accounts():
    print(Fore.CYAN + "\n[+] Checking critical accounts status...\n")

    admin = run("net user administrator")
    guest = run("net user guest")

    def is_enabled(output):
        return "Account active" in output and "Yes" in output

    print("--- Administrator Account ---")
    if is_enabled(admin):
        print(Fore.RED + "[WARNING] Administrator account is ENABLED")
        log("<p style='color:red'>Administrator account: ENABLED</p>")
    else:
        print(Fore.GREEN + "[OK] Administrator account is disabled")
        log("<p style='color:green'>Administrator account: Disabled</p>")

    print("\n--- Guest Account ---")
    if is_enabled(guest):
        print(Fore.RED + "[WARNING] Guest account is ENABLED")
        log("<p style='color:red'>Guest account: ENABLED</p>")
    else:
        print(Fore.GREEN + "[OK] Guest account is disabled")
        log("<p style='color:green'>Guest account: Disabled</p>")

def list_users():
    print(Fore.CYAN + "\n[+] Listing Local Users...\n")
    users = run("net user")
    print(users)
    log("<h3>Local Users</h3><pre>" + users + "</pre>")

def password_policy():
    print(Fore.CYAN + "\n[+] Checking Password Policy...\n")
    policy = run("net accounts")
    print(policy)
    log("<h3>Password Policy</h3><pre>" + policy + "</pre>")

def failed_logins():
    print(Fore.CYAN + "\n[+] Recent Failed Login Attempts...\n")

    if platform.system() != "Windows":
        print("This check only works on Windows systems.")
        return

    cmd = 'wevtutil qe Security /q:"*[System[(EventID=4625)]]" /f:text /c:10'
    logs = run(cmd)

    if logs.strip() and "Event" in logs:
        print(Fore.YELLOW + logs)
        log("<h3>Failed Login Attempts</h3><pre>" + logs + "</pre>")
    else:
        print(Fore.GREEN + "No recent failed login attempts found.")
        log("<p style='color:green'>No recent failed login attempts</p>")

def generate_report():
    print(Fore.CYAN + "\n[+] Generating HTML Security Report...\n")

    html = f"""
    <html>
    <head>
        <title>Windows Security Audit Report</title>
        <style>
            body {{ font-family: Arial; margin: 20px; }}
            h2 {{ color: #2c3e50; }}
            pre {{ background: #f4f4f4; padding: 10px; }}
        </style>
    </head>
    <body>
        <h2>Windows Security Audit Report</h2>
        <p>Date: {datetime.now()}</p>
        <hr>
        {''.join(report_data)}
    </body>
    </html>
    """

    with open(HTML_REPORT, "w", encoding="utf-8") as f:
        f.write(html)

    print(Fore.GREEN + f"Report saved as: {HTML_REPORT}")

def main():
    print(Fore.MAGENTA + "==== Windows Security Audit Tool ====")

    admin_privilege_check()
    check_accounts()
    list_users()
    password_policy()
    failed_logins()
    generate_report()

    print(Fore.MAGENTA + "\n==== Audit Complete ====")

if __name__ == "__main__":

    if not is_admin():
        print(Fore.YELLOW + "🛡️ Requesting admin privileges...\n")

        params = " ".join([f'"{arg}"' for arg in sys.argv])

        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
            sys.exit(0)

        except Exception as e:
            print(Fore.RED + f"❌ Failed to elevate privileges: {e}")
            input("Press Enter to exit...")
            sys.exit(1)

    else:
        main()
        input("\nPress Enter to exit...")
