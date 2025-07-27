from database import get_db
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from sqlalchemy.orm import Session
from models import FirewallRule  # Assuming this is your model file

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

def postPacketInputTracer(rule, username, password, secret, db: Session) -> list:
    """
    Generate Packet Tracer commands for firewall rules and set post_action and post_reason.
    Handles multiple ports by testing each port individually.
    Returns a list of tuples: (firewall_ip, command, rule_id).
    """
    firewallIP = rule.firewallIP
    context_name = rule.context
    if not rule:
        print(f"No rule found for src_ip={rule.source_ip} and dst_ip={rule.dest_ip}")
        return []

    # Determine protocol and ports
    protocol = rule.protocol.lower() if rule.protocol else "tcp"
    ports = [p.strip() for p in rule.multiple_ports.split(',')] if rule.multiple_ports else ["80"]
    
    # Initialize results tracking
    port_results = []
    commands_executed = []
    all_allow = True
    all_drop = True
    detailed_reasons = []  # To store detailed port-specific reasons

    try:
        # Source firewall
        print("For src_device")
        src_device = {
            'device_type': 'cisco_asa',
            'ip': firewallIP,
            'username': username,
            'password': password,
            'secret': secret,
            "session_log": f"postPacketInputTracer.log",
        }
        
        if firewallIP is not None:
            with ConnectHandler(**src_device) as conn:
                conn.enable()
                if context_name is not None:
                    conn.send_command("changeto system", expect_string=".+#")
                    conn.send_command(f"change context {context_name}", expect_string=".+#")
                
                # Test each port individually
                for port in ports:
                    command = f"packet-tracer input {rule.src_interface} {protocol} {rule.source_ip} 12345 {rule.dest_ip} {port}"
                    print(f"Packet Tracer Command for port {port}: {command}")
                    
                    try:
                        output = conn.send_command(command)
                        print(f"Output for port {port}:")
                        print(output)
                        
                        action, reason = parse_packet_tracer_output(output)
                        
                        # Create detailed port result
                        port_result = {
                            "port": port,
                            "action": action,
                            "reason": reason
                        }
                        port_results.append(port_result)
                        
                        # Track overall status
                        if action != "allow":
                            all_allow = False
                        if action != "drop":
                            all_drop = False
                            
                        commands_executed.append((firewallIP, command, rule.id))
                        
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
                        commands_executed.append((firewallIP, command, rule.id))
                
                # Create detailed reason description
                detailed_reason = "\n".join([
                    f"Port {res['port']}: {res['action'].upper()} - {res['reason']}"
                    for res in port_results
                ])
                
                # Determine overall result
                if all_allow:
                    rule.post_action = "Allowed"
                    rule.post_reason = f"All ports allowed\n{detailed_reason}"
                elif all_drop:
                    rule.post_action = "Drop"
                    rule.post_reason = f"All ports dropped\n{detailed_reason}"
                else:
                    rule.post_action = "Mixed"
                    rule.post_reason = f"Mixed results\n{detailed_reason}"
                    
                db.commit()
                print(f"Updated rule {rule.id}: post_action={rule.post_action}")
                print(f"Detailed reason:\n{rule.post_reason}")
                
        return commands_executed

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        error_msg = f"Connection error: {str(e)}"
        rule.post_action = "Connection Error"
        rule.post_reason = error_msg
        db.commit()
        print(error_msg)
        return commands_executed
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        rule.post_action = "Error"
        rule.post_reason = error_msg
        db.commit()
        print(error_msg)
        return commands_executed