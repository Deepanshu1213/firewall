import logging
from fastapi import HTTPException
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

def failOver(ip,username,password,secret) -> bool : 
    if not ip :
        print("No ip for failover")
        return True
    device = {
    'device_type': 'cisco_asa',
    'ip': ip,
    'username': username,
    'password': password,
    'secret': password # Enable secret for privileged mode
    }
    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()
            output = net_connect.send_command("show failover state")
            lines = output.splitlines()
            print("*"*10,lines)
            if len(lines) < 4:
                logging.warning(f"Unexpected output format from {ip}: fewer than 4 lines.")
                return False
            fourth_line = lines[3].strip()
            stand_by =lines[5].strip()
            logging.debug(f"Failover state detected and got {fourth_line}")
            print(f"Commands pushed to {ip}: {output}")
            if "Active" in fourth_line:
                return True
            if "Disabled" in fourth_line and "Not Detected" in stand_by:
                return True
            #lets try here
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        raise HTTPException(status_code=500, detail=f"Failed to connect to firewall {ip}: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to push commands to {ip}: {str(e)}")