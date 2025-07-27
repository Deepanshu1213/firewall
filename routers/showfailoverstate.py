import logging
import re
from fastapi import HTTPException
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import time
def show_failover_state(ip, username, password, secret, context_name=None) -> bool:
    print("Show failover command executing......")
    if not ip:
        logging.info("No IP provided for failover state check.")
        return {"is_active": True, "message": "No IP provided, assuming active."}
    print(ip)
    device = {
        'device_type': 'cisco_asa',
        'ip': ip,
        'username': username,
        'password': password,
        "global_delay_factor": 2,
        "session_log": f"asa_{ip}.log",
        'secret': secret
    }

    try:
        with ConnectHandler(**device) as net_connect:
            print("Trying to connect to firewall")
            net_connect.enable()

            # Command 1: Change to system context
            time.sleep(10)
            net_connect.send_command("changeto system",expect_string=r".+#")

            print("showfailover line number 43","*"*50)
           # print(net_connect.send_command("change system"))
            print(f"Switched to system context on {ip}")
            time.sleep(10)
            # Command 2: Show failover state
            output = net_connect.send_command("show failover state",expect_string=r".+#")
            print(f"Failover state output from {ip}: {output}")

            # Parse output using regex
            lines = output.splitlines()
            this_host_section = None
            for i, line in enumerate(lines):
                if re.match(r"^\s*This host\s*-", line):
                    this_host_section = lines[i:]
                    break

            if not this_host_section:
                logging.warning(f"Could not find 'This host' section in failover state output from {ip}")
                return False

            # Check Group 1 and Group 2 states
            group1_active = False
            group2_active = False
            for line in this_host_section:
                if "Group 1" in line and "Active" in line:
                    group1_active = True
                if "Group 2" in line and "Active" in line:
                    group2_active = True

            if group1_active and group2_active:
                return True
            else:
                return False

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        logging.error(f"Failed to connect to firewall {ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to connect to firewall {ip}: {str(e)}")
    except Exception as e:
        logging.error(f"Failed to execute commands on {ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to execute commands on {ip}: {str(e)}")