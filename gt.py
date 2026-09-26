import os

def ping_host(user_ip):
    # Vulnerable direct string formatting in shell execution
    command = f"ping -c 1 {user_ip}"
    return os.system(command)