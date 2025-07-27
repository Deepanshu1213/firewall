from database import get_db
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from sqlalchemy.orm import Session
from models import FirewallRule

def parse_packet_tracer_output(output):
    """
    Parse the Packet Tracer output to extract the action and reason.
    - For "allow" action, check if "permit" is in the output.
    - For "drop" action, capture the Drop-reason line.
    """
    lines = output.strip().splitlines()
    last_four_lines = lines[-4:] if len(lines) >= 4 else lines

    action = "unknown"
    reason = "unknown"

    # Search the last 4 lines for Action
    for line in last_four_lines:
        if "Action:" in line:
            action_part = line.split("Action:")[1].strip()
            action = action_part.lower()
            break  # Action found, no need to check further

    if action == "allow":
        # Search the entire output for "permit"
        for line in lines:
            if "permit" in line:
                reason = line
                break
    elif action == "drop":
        # Search the last 4 lines for Drop-reason
        for line in last_four_lines:
            if "Drop-reason:" in line:
                reason = line.strip()  # Capture the entire Drop-reason line
                break

    return action, reason

def packetInputTracer(rule, username, password, secret, context_name, db: Session):
    """
    Generate Packet Tracer commands for each port in the firewall rule and set src_Action and src_Reason.
    Only runs on source firewall using source interface.
    """
    print("*"*50, "in packet tracer")
    src_interface = rule.src_interface
    firewall_ip = rule.firewallIP
    # Refresh the rule from database
    rule = db.query(FirewallRule).filter_by(id=rule.id).first()
    if not rule:
        print(f"No rule found with ID {rule.id}")
        return

    # Determine protocol and ports
    protocol = rule.protocol.lower() if rule.protocol else "tcp"
    ports = [p.strip() for p in rule.multiple_ports.split(',')] if rule.multiple_ports else ["80"]
    
    # Initialize results tracking
    port_results = []
    all_allow = True
    all_drop = True
    detailed_reasons = []  # To store detailed port-specific reasons

    try:
        # Device configuration for source firewall
        src_device = {
            'device_type': 'cisco_asa',
            'ip': firewall_ip,
            'username': username,
            'password': password,
            'secret': secret,
            "session_log": f"tracer_interface.log",
        }
        
        if firewall_ip:
            with ConnectHandler(**src_device) as conn:
                conn.enable()
                
                # Change context if needed
                if context_name is not None:
                    conn.send_command("changeto system", expect_string=r".+#")
                    conn.send_command(f"change context {context_name}", expect_string=r".+#")
                
                # Iterate over each port
                for port in ports:
                    # Generate Packet Tracer command for this port
                    command = f"packet-tracer input {src_interface} {protocol} {rule.source_ip} 12345 {rule.dest_ip} {port}"
                    print(f"Packet Tracer Command for port {port}: {command}")
                    
                    try:
                        # Run packet tracer command
                        output = conn.send_command(command)
                        print(f"Packet Tracer Output for port {port}:")
                        print(output)
                        
                        # Parse output
                        action, reason = parse_packet_tracer_output(output)
                        
                        # Create detailed port result
                        port_result = {
                            "port": port,
                            "action": action,
                            "reason": reason
                        }
                        port_results.append(port_result)
                        
                        # Track overall actions
                        if action != "allow":
                            all_allow = False
                        if action != "drop":
                            all_drop = False
                            
                    except Exception as e:
                        error_msg = f"Error executing command: {str(e)}"
                        port_result = {
                            "port": port,
                            "action": "error",
                            "reason": error_msg
                        }
                        port_results.append(port_result)
                        all_allow = False
                        all_drop = False
                
                # Create detailed reason description
                detailed_reason = "\n".join([
                    f"Port {res['port']}: {res['action'].upper()} - {res['reason']}"
                    for res in port_results
                ])
                
                # Determine overall action and reason
                if all_allow:
                    rule.Action = "Allowed"
                    rule.Reason = f"All ports allowed\n{detailed_reason}"
                elif all_drop:
                    rule.Action = "Drop"
                    rule.Reason = f"All ports dropped\n{detailed_reason}"
                else:
                    rule.Action = "Mixed"
                    rule.Reason = f"Mixed results\n{detailed_reason}"
                
                print(f"Updated rule {rule.id}: Action={rule.Action}")
                print(f"Detailed reason:\n{rule.Reason}")
                db.commit()
        else:
            print("No firewall IP provided")
            
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        error_msg = f"Connection error: {str(e)}"
        print(error_msg)
        rule.Action = "Connection Error"
        rule.Reason = error_msg
        db.commit()
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        print(error_msg)
        rule.Action = "Error"
        rule.Reason = error_msg
        db.commit()