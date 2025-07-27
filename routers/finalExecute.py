from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from routers.postPacketInputTracer import postPacketInputTracer
from database import get_db
from models import FirewallRule, FirewallList, Risk
import datetime

router = APIRouter()

async def run_batch_process(db: Session):
    """
    Compare Src_ip and Dst_IP between Risk and itsr_rules tables and copy Risk_Description
    from Risk to itsr_rules where there is a match.
    """
    try:
        # Fetch all rules and risks to log and debug
        rules = db.query(FirewallRule).filter(FirewallRule.final_status == "Pending").all()
        risks = db.query(Risk).all()
        print(f"Found {len(rules)} pending rules and {len(risks)} risk entries")
        
        for rule in rules:
            matched = False
            for risk in risks:
                rule_source_ip = rule.source_ip.strip() if rule.source_ip else ""
                rule_dest_ip = rule.dest_ip.strip() if rule.dest_ip else ""
                risk_src_ip = risk.Src_ip.strip() if risk.Src_ip else ""
                risk_dst_ip = risk.Dst_IP.strip() if risk.Dst_IP else ""
                
                if rule_source_ip == risk_src_ip and rule_dest_ip == risk_dst_ip:
                    print(f"Match found for rule {rule.itsr_number}: {rule_source_ip} -> {risk_src_ip}, {rule_dest_ip} -> {risk_dst_ip}")
                    rule.Risk_Description = risk.Risk_Description
                    matched = True
                    break
            if not matched:
                print(f"No match found for rule {rule.itsr_number}: {rule_source_ip}, {rule_dest_ip}")
        
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Batch process failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Batch process failed: {str(e)}")

def sanitize_email(email: str) -> str:
    """Sanitize email for use in object group names by replacing special characters."""
    return email.replace("@", "-").replace(".", "-dot-")

def generate_asa_acl_commands(rule: FirewallRule) -> list:
    """
    Generate Cisco ASA commands to create object groups and an ACL based on the firewall rule.
    Returns a list of commands or raises an error if required fields are missing.
    """
    creation_time = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    if not all([rule.protocol, rule.source_ip, rule.dest_ip]):
        raise ValueError(f"Rule {rule.id} is missing required fields: protocol, source_ip, or dest_ip")

    sanitized_email = sanitize_email(rule.email)
    src_group = f"{rule.itsr_number}_{sanitized_email}_{creation_time}_{rule.Security_Exception_number}_{rule.Security_Exception_expiry_date}_SRC"
    dest_group = f"{rule.itsr_number}_{sanitized_email}_{creation_time}_{rule.Security_Exception_number}_{rule.Security_Exception_expiry_date}_DST"
    port_group = f"{rule.itsr_number}_PORT"

    source_ips = [ip.strip() for ip in rule.source_ip.split() if ip.strip()]
    dest_ips = [ip.strip() for ip in rule.dest_ip.split() if ip.strip()]

    commands = []

    commands.append(f"object-group network {src_group}")
    for ip in source_ips:
        if "-" in ip:
            split_ip, subnet = ip.split("-")
            commands.append(f"network-object {split_ip} {subnet}")
        else:
            commands.append(f"network-object host {ip}")
        
    commands.append(f"object-group network {dest_group}")
    for ip in dest_ips:
        if "-" in ip:
            split_ip, subnet = ip.split("-")
            commands.append(f"network-object {split_ip} {subnet}")
        else:
            commands.append(f"network-object host {ip}")

    has_ports = bool(rule.multiple_ports or 
                     (rule.port_range_start and rule.port_range_end))
    if rule.protocol.lower() in ['tcp', 'udp'] and has_ports:
        commands.append(f"object-group service {port_group} {rule.protocol.lower()}")
        if rule.multiple_ports:
            ports = [port.strip() for port in rule.multiple_ports.split(",") if port.strip()]
            for port in ports:
                commands.append(f"port-object eq {port}")
        if rule.port_range_start and rule.port_range_end:
            commands.append(f"port-object range {rule.port_range_start} {rule.port_range_end}")

    if rule.src_access_group is None:
        return {"message": "No access-group found acl can not be created"}
    acl_cmd = f"access-list {rule.src_access_group} line 1 extended permit {rule.protocol.lower()} object-group {src_group} object-group {dest_group}"
    if rule.protocol.lower() in ['tcp', 'udp'] and has_ports:
        acl_cmd += f" object-group {port_group}"
    commands.append(acl_cmd)
    commands.append("wr")
    return commands

def push_command_to_firewall(ip: str, username: str, password: str, commands: list, context: str = None):
    """Push commands to the Cisco ASA firewall via SSH using Netmiko."""
    if not ip:
        print("No firewall IP provided")
        return

    device = {
        'device_type': 'cisco_asa',
        'ip': ip,
        'username': username,
        'password': password,
        'secret': password
    }
    try:
        with ConnectHandler(**device) as net_connect:
            net_connect.enable()
            
            if context:
                net_connect.send_command("changeto system", expect_string=r".+#")
                net_connect.send_command(f"change context {context}", expect_string=r".+#")
            
            output = net_connect.send_config_set(commands)
            print(f"Commands pushed to {ip}: {output}")
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        raise HTTPException(status_code=500, detail=f"Failed to connect to firewall {ip}: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to push commands to {ip}: {str(e)}")

@router.post("/final_execute")
def final_execute(db: Session = Depends(get_db), current_user: str = "admin"):
    """
    Execute Cisco ASA ACL commands for all pending firewall rules created by the current user.
    - Runs batch process to copy Risk_Description from Risk to itsr_rules.
    - Filters rules where final_status is "Pending".
    - Generates and pushes ASA commands using object groups.
    - Updates rule status to "Completed" on success.
    - Returns the itsr_number(s) of the processed rules.
    """
    try:
        run_batch_process(db)
        print("Batch process completed: Copied Risk_Description from Risk to itsr_rules")
    except HTTPException as he:
        print(f"Batch process error: {he.detail}")
        raise he

    pending_rules = db.query(FirewallRule).filter(
        FirewallRule.final_status == "Pending",
        FirewallRule.created_by == current_user
    ).all()

    if not pending_rules:
        raise HTTPException(status_code=404, detail="No pending rules found for the current user.")
    
    processed_itsr_numbers = set()  # To store unique itsr_numbers of processed rules

    for rule in pending_rules:
        firewall = db.query(FirewallList).filter(
            FirewallList.firewall_hostname == rule.Firewall
        ).first()
        
        if not firewall:
            print(f"Skipping rule {rule.id}: Firewall hostname {rule.Firewall} not found")
            continue
            
        firewall_ip = firewall.ip
        
        try:
            commands = generate_asa_acl_commands(rule)
            print(f"Executing commands on {rule.Firewall} ({firewall_ip})")
            push_command_to_firewall(
                firewall_ip, 
                "amishra11", 
                "Dru56%Pty7", 
                commands,
                context=rule.context
            )
            postPacketInputTracer(rule=rule,username="amishra11",password="Dru56%Pty7",secret="Dru56%Pty7",db=db)

            rule.final_status = "Completed" 
            rule.updated_at = datetime.datetime.utcnow()
            db.add(rule)
            processed_itsr_numbers.add(rule.itsr_number)  # Add itsr_number to the set
            db.commit()
            
        except ValueError as ve:
            print(f"Skipping rule {rule.id}: {str(ve)}")
            continue
        except HTTPException as he:
            print(f"HTTP error for rule {rule.id}: {he.detail}")
            rule.final_status = f"Error: {he.detail}"
            db.add(rule)
            db.commit()
        except Exception as e:
            print(f"Failed to process rule {rule.id}: {str(e)}")
            rule.final_status = f"Error: {str(e)}"
            db.add(rule)
            db.commit()

    return {
        "message": "Firewall rules processed successfully.",
        "processed_itsr_numbers": list(processed_itsr_numbers)  # Return the list of itsr_numbers
    }