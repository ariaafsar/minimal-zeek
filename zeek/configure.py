import os
from dotenv import load_dotenv

load_dotenv()
interface = os.getenv("INTERFACE")
zeek_script = os.getenv("ZEEK_SCRIPT")
log_interval = os.getenv("LOG_INTERVAL")
log_expire = os.getenv("LOG_EXPIRE")


import os

def update_config(file_path, key, value):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"{file_path} not found")

    with open(file_path, "r") as f:
        lines = f.readlines()

    new_lines = []
    key_found = False

    for line in lines:
        stripped = line.strip()

        # رد کردن کامنت‌ها و خطوط خالی
        if stripped.startswith("#") or "=" not in stripped:
            new_lines.append(line)
            continue

        current_key = stripped.split("=", 1)[0].strip()

        if current_key == key:
            if not key_found:
                new_lines.append(f"{key}={value}\n")
                key_found = True
            # اگر تکراری باشه ردش می‌کنیم (duplicate حذف میشه)
        else:
            new_lines.append(line)

    if not key_found:
        new_lines.append(f"{key}={value}\n")

    with open(file_path, "w") as f:
        f.writelines(new_lines)

def add_line(file_path, line):
    """
    Ensures that a given line exists in a file.
    If the line doesn't exist, it appends it at the end.

    :param file_path: Path to the file
    :param line: The exact line to check or append
    """
    # Make sure the file exists
    if not os.path.exists(file_path):
        # Create the file if it doesn’t exist
        with open(file_path, "w") as f:
            f.write(line.strip() + "\n")
        print(f"File created and line added: {line.strip()}")
        return

    # Read all lines
    with open(file_path, "r") as f:
        lines = [l.strip() for l in f.readlines()]

    # Check if the line exists
    if line.strip() not in lines:
        with open(file_path, "a") as f:
            f.write(line.strip() + "\n")
        print(f"Line added: {line.strip()}")
    else:
        print(f"Line already exists: {line.strip()}")

def add_file(file_path, text):
    """
    Ensures a file exists. If it doesn't, creates it and writes the given text.
    
    :param file_path: Path to the file
    :param text: Text content to write if the file doesn't exist
    """
    if not os.path.exists(file_path):
        # Create directories if needed
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        # Create the file and write the text
        with open(file_path, "w") as f:
            f.write(text)
        print(f"File created at {file_path} with provided text.")
    else:
        print(f"File already exists: {file_path}")

def comment_line_in_file(line_to_comment: str, file_path: str):
    """
    Comments out the first occurrence of a line in a file.

    :param line_to_comment: The exact line to comment.
    :param file_path: Path to the file.
    """
    with open(file_path, 'r') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        # Strip newline and whitespace for comparison
        if line.strip() == line_to_comment.strip():
            # Add '#' if it's not already commented
            if not line.lstrip().startswith('#'):
                lines[i] = '#' + line
            break  # Comment only the first match

    with open(file_path, 'w') as f:
        f.writelines(lines)

def clear_file(file_path: str):
    """
    Deletes all content of the file at the given path.

    :param file_path: Path to the file to clear.
    """
    # Open the file in write mode, which truncates it
    with open(file_path, 'w') as f:
        pass  # Writing nothing effectively clears the file

#deactivating the default logers
comment_line_in_file("@load base/protocols/conn", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/dce-rpc", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/dhcp", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/dnp3", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/dns", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/finger", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/ftp", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/http", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/imap", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/irc", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/krb", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/ldap", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/modbus", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/mqtt", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/mysql", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/ntlm", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/ntp", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/pop3", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/postgresql", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/quic", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/radius", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/rdp", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/redis", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/rfb", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/sip", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/snmp", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/smb", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/smtp", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/socks", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/ssh", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/ssl", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/syslog", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/websocket", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/tunnels", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/protocols/xmpp", "/opt/zeek/share/zeek/base/init-default.zeek")
comment_line_in_file("@load base/files/x509", "/opt/zeek/share/zeek/base/init-default.zeek")
#reconfiguring local.zeek
clear_file("/opt/zeek/share/zeek/site/local.zeek")
add_line("/opt/zeek/share/zeek/site/local.zeek", f"@load {str(zeek_script)}")
add_line("/opt/zeek/share/zeek/site/local.zeek", "@load policy/tuning/json-logs.zeek")
#change zeekctl.cfg
update_config("/opt/zeek/etc/zeekctl.cfg", "LogRotationInterval", str(log_interval))
update_config("/opt/zeek/etc/zeekctl.cfg", "LogExpireInterval", str(log_expire))
#chhange zeek's interface
update_config("/opt/zeek/etc/node.cfg", "interface", str(interface))
