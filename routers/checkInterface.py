from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from models import FirewallRule
import re 
from routers.packetInputTracer import *
import time

def get_acl_name_for_interface(firewall_ip, interface, username, password, secret, context_name):
    if not firewall_ip or not interface:
        return None
        
    device = {
        'device_type': 'cisco_asa',
        'ip': firewall_ip,
        'username': username,
        'password': password,
        'secret': secret,
        'session_log': 'acl_lookup.log'
    }

    try:
        with ConnectHandler(**device) as conn:
            conn.enable()

            if context_name:
                conn.send_command("changeto system", expect_string=r".+#")
                time.sleep(2)
                conn.send_command(f"change context {context_name}", expect_string=r".+#")
                time.sleep(2)

            # conn.send_command("terminal pager 0", expect_string=r".+#")
            output = conn.send_command("show run access-group")
            for line in output.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2 and parts[-1].lower() == interface.lower():
                    return parts[1]  # Return ACL name low_sec_nonlb_prod
            return None

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"Connection error: {str(e)}")
        return None
    except Exception as e:
        print(f"Error getting ACL: {str(e)}")
        return None

def extract_interface(route_output):
    """Extract the interface name from the 'show route' command output."""
    candidates = re.findall(r'via\s+([^\s,()]+)', route_output)
    interfaces = [i for i in candidates if i.lower() != 'interface']
    return interfaces[-1] if interfaces else None

def extract_default_interface(firewall_ip, username, password, secret, context_name):
    if not firewall_ip:
        return None
        
    device = {
        'device_type': 'cisco_asa',
        'ip': firewall_ip,
        'username': username,
        'password': password,
        "global_delay_factor": 2,
        "session_log": f"default_interface.log",
        'secret': secret
    }
    try:
        with ConnectHandler(**device) as conn:
            conn.enable()
            
            if context_name:
                conn.send_command("changeto system", expect_string=r".+#")
                time.sleep(2)
                conn.send_command(f"change context {context_name}", expect_string=r".+#")
                
            conn.send_command("terminal pager 0", expect_string=r".+#")
            output = conn.send_command("show route")
            
            for line in output.splitlines():
                if "S*" in line:
                    return line.split(",")[-1].strip()
                    
    except Exception as e:
        print(f"Error getting default interface: {str(e)}")
        return None

def extract_interface_for_ip(firewall_ip, username, password, secret, context_name, ip):
    if not firewall_ip or not ip:
        return None
        
    device = {
        'device_type': 'cisco_asa',
        'ip': firewall_ip,
        'username': username,
        'password': password,
        "session_log": f"interface.log",
        'secret': secret
    }
    try:
        with ConnectHandler(**device) as conn:
            conn.enable()
            if context_name: 
                conn.send_command("changeto system")   
                conn.send_command(f"change context {context_name}", expect_string=r".+#")
                
            output = conn.send_command(f"show route {ip}")
            return extract_interface(output)
            
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"Error connecting to firewall: {str(e)}")
        return None
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return None

def update_firewall_interfaces_for_rule(rule, username, password, secret, db):
    try:
        # Only process source firewall for both interfaces
        firewall_ip = rule.firewallIP
        context_name = rule.context
        src_ip = rule.source_ip
        dst_ip = rule.dest_ip

        # Get source interface
        src_interface = extract_interface_for_ip(
            firewall_ip=firewall_ip,
            username=username,
            password=password,
            secret=secret,
            context_name=context_name,
            ip=src_ip
        ) if src_ip else None

        # Get destination interface on same firewall
        dst_interface = extract_interface_for_ip(
            firewall_ip=firewall_ip,
            username=username,
            password=password,
            secret=secret,
            context_name=context_name,
            ip=dst_ip
        ) if dst_ip else None

        # Handle missing interfaces
        if not src_interface and firewall_ip:
            src_interface = extract_default_interface(
                firewall_ip=firewall_ip,
                username=username,
                password=password,
                secret=secret,
                context_name=context_name
            )
        
        if not dst_interface and firewall_ip and dst_ip:
            dst_interface = extract_default_interface(
                firewall_ip=firewall_ip,
                username=username,
                password=password,
                secret=secret,
                context_name=context_name
            )

        # Update rule with interfaces
        rule.src_interface = src_interface
        rule.dst_interface = dst_interface

        # Set status if no route found
        if (src_ip and not src_interface) or (dst_ip and not dst_interface):
            rule.pre_status = "No route available"
            rule.post_status = "No route available"
            return

        # Determine inline status (both interfaces on same firewall)
        rule.inLine = "not inline" if src_interface == dst_interface else "inline"

        # Run packet tracer for inline rules on same firewall
        if rule.inLine == "inline" and src_interface and dst_interface:
            packetInputTracer(
                rule=rule,
                username=username,
                password=password,
                secret=secret,
                context_name=context_name,
                db=db
            )
            pass
        # Get access groups for both interfaces on same firewall
        if src_interface:
            rule.src_access_group = get_acl_name_for_interface(
                firewall_ip,
                src_interface,
                username, 
                password,
                secret,
                context_name=context_name
            )
        
        if dst_interface:
            rule.dst_access_group = get_acl_name_for_interface(
                firewall_ip,  # Same as source firewall
                dst_interface,
                username, 
                password,
                secret,
                context_name=context_name  # Same as source context
            )

    except Exception as e:
        print(f"Error processing rule: {str(e)}")
        rule.pre_status = f"Error: {str(e)}"