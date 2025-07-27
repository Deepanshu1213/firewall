from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from database import get_db, Base, engine
from sqlalchemy.orm import Session
from models import FirewallRule, FirewallList, Risk
from jinja2 import Environment, FileSystemLoader
from routers import finalExecute, checkInterface
from routers.failOver import failOver
from routers.showfailoverstate import show_failover_state
from pydantic import BaseModel
from typing import Optional
from datetime import date

app = FastAPI()

# Set up Jinja2 environment
templates = Environment(loader=FileSystemLoader("templates"))
app.include_router(finalExecute.router)

# Create tables
FirewallList.__table__.create(bind=engine, checkfirst=True)
FirewallRule.__table__.create(bind=engine, checkfirst=True)
Risk.__table__.create(bind=engine, checkfirst=True)

# Dependency to get DB session
def get_database():
    yield from get_db()

class RuleUpdate(BaseModel):
    itsr_number: str
    source_ip: str
    dest_ip: str
    risk_description: Optional[str] = None
    security_exception_number: Optional[str] = None
    security_exception_expiry_date: Optional[date] = None

async def run_batch_process(db: Session):
    try:
        db.execute(
            FirewallRule.__table__.update()
            .where(FirewallRule.source_ip == Risk.Src_ip)
            .where(FirewallRule.dest_ip == Risk.Dst_IP)
            .values(Risk_Description=Risk.Risk_Description)
        )
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Batch process failed: {str(e)}")

@app.post("/run-batch", response_class=JSONResponse)
async def run_batch(db: Session = Depends(get_database)):
    await run_batch_process(db)
    return {"message": "Batch process completed successfully"}

@app.put("/update-rule", response_class=JSONResponse)
async def update_rule(update: RuleUpdate, db: Session = Depends(get_database)):
    try:
        rule = db.query(FirewallRule).filter(
            FirewallRule.itsr_number == update.itsr_number,
            FirewallRule.source_ip == update.source_ip,
            FirewallRule.dest_ip == update.dest_ip
        ).first()
        
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        
        if update.risk_description is not None:
            rule.Risk_Description = update.risk_description
        if update.security_exception_number is not None:
            rule.Security_Exception_number = update.security_exception_number
        if update.security_exception_expiry_date is not None:
            rule.Security_Exception_expiry_date = update.security_exception_expiry_date
        
        db.commit()
        db.refresh(rule)
        return {"message": "Rule updated successfully", "data": rule.__dict__}
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Update failed: {str(e)}")

@app.post("/update-rule", response_class=HTMLResponse)
async def update_rule_form(request: Request, db: Session = Depends(get_database)):
    form_data = await request.form()
    try:
        rule = db.query(FirewallRule).filter(
            FirewallRule.itsr_number == form_data.get("itsr_number"),
            FirewallRule.source_ip == form_data.get("source_ip"),
            FirewallRule.dest_ip == form_data.get("dest_ip")
        ).first()
        
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        
        if form_data.get("risk_description"):
            rule.Risk_Description = form_data.get("risk_description")
        if form_data.get("security_exception_number"):
            rule.Security_Exception_number = form_data.get("security_exception_number")
        if form_data.get("security_exception_expiry_date"):
            rule.Security_Exception_expiry_date = form_data.get("security_exception_expiry_date")
        
        db.commit()
        db.refresh(rule)
        
        rules = db.query(FirewallRule).filter(FirewallRule.final_status != "Completed").all()
        firewalls = db.query(FirewallList).all()
        firewall_data = [
            {
                "firewall_hostname": fw.firewall_hostname,
                "context_names": [fw.context_name] if fw.context_name else []
            }
            for fw in firewalls
        ]
        return templates.get_template("index.html").render(
            request=request,
            rules=rules,
            firewalls=firewall_data,
            message="Rule updated successfully!"
        )
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Update failed: {str(e)}")

@app.post("/update-status", response_class=JSONResponse)
async def update_status(request: Request, db: Session = Depends(get_database)):
    form_data = await request.form()
    try:
        itsr_number = form_data.get("itsr_number")
        source_ip = form_data.get("source_ip")
        dest_ip = form_data.get("dest_ip")
        final_status = form_data.get("final_status")

        if final_status not in ["Pending", "Cancelled"]:
            raise HTTPException(status_code=400, detail="Invalid status value")

        rule = db.query(FirewallRule).filter(
            FirewallRule.itsr_number == itsr_number,
            FirewallRule.source_ip == source_ip,
            FirewallRule.dest_ip == dest_ip
        ).first()

        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")

        rule.final_status = final_status
        db.commit()
        db.refresh(rule)
        return {"message": f"Status updated to {final_status}"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Status update failed: {str(e)}")

@app.post("/delete-rule-ui", response_class=JSONResponse)
async def delete_rule_ui(request: Request, db: Session = Depends(get_database)):
    form_data = await request.form()
    try:
        itsr_number = form_data.get("itsr_number")
        source_ip = form_data.get("source_ip")
        dest_ip = form_data.get("dest_ip")

        rule = db.query(FirewallRule).filter(
            FirewallRule.itsr_number == itsr_number,
            FirewallRule.source_ip == source_ip,
            FirewallRule.dest_ip == dest_ip
        ).first()

        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")

        # No need to change final_status; it should remain "Cancelled"
        # Just commit to ensure the database is in sync
        db.commit()
        db.refresh(rule)
        return {"message": "Rule remains Cancelled and removed from UI"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to process rule: {str(e)}")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, db: Session = Depends(get_database)):
    # Filter out rules with final_status of either Completed or Cancelled
    rules = db.query(FirewallRule).filter(
        FirewallRule.final_status.notin_(["Completed", "Cancelled"])
    ).all()
    firewalls = db.query(FirewallList).all()
    # Fetch all risks for prefix matching
    risks = db.query(Risk).all()
    
    # Match IP prefixes for each rule
    for rule in rules:
        matched_risk_description = None
        for risk in risks:
            # Trim whitespace and ensure IPs are compared correctly
            rule_source_ip = rule.source_ip.strip() if rule.source_ip else ""
            rule_dest_ip = rule.dest_ip.strip() if rule.dest_ip else ""
            risk_src_ip = risk.Src_ip.strip() if risk.Src_ip else ""
            risk_dst_ip = risk.Dst_IP.strip() if risk.Dst_IP else ""
            
            if (
                # Case 1: rule.source_ip matches risk.Src_ip or risk.Dst_IP
                (rule_source_ip and (rule_source_ip.startswith(risk_src_ip) or rule_source_ip.startswith(risk_dst_ip)))
                and
                # Case 2: rule.dest_ip matches risk.Src_ip or risk.Dst_IP
                (rule_dest_ip and (rule_dest_ip.startswith(risk_src_ip) or rule_dest_ip.startswith(risk_dst_ip)))
            ):
                matched_risk_description = risk.Risk_Description
                break
        # Attach matched Risk_Description as a transient attribute, fallback to rule.Risk_Description
        setattr(rule, 'matched_Risk_Description', matched_risk_description or rule.Risk_Description or '')
    
    firewall_data = [
        {
            "firewall_hostname": fw.firewall_hostname,
            "context_names": [fw.context_name] if fw.context_name else []
        }
        for fw in firewalls
    ]
    return templates.get_template("index.html").render(
        request=request,
        rules=rules,
        firewalls=firewall_data
    )

@app.post("/submit-rule")
async def submit_rule(request: Request, db: Session = Depends(get_database)):
    form_data = await request.form()
    firewall_display = form_data.get("Firewall")

    def parse_firewall_value(display_value):
        if not display_value or display_value == "None":
            return None, None
        parts = display_value.split(":")
        hostname = parts[0]
        context = parts[1] if len(parts) > 1 else None
        return hostname, context

    firewall_hostname, context = parse_firewall_value(firewall_display)

    firewall = db.query(FirewallList).filter(FirewallList.firewall_hostname == firewall_hostname).first() if firewall_hostname else None

    if not firewall:
        raise HTTPException(status_code=404, detail="Source firewall not found")
    
    firewallIP = firewall.ip
    if context:
        if not show_failover_state(
            firewallIP,
            username="amishra11",
            password="Dru56%Pty7",
            secret="Dru56%Pty7",
            context_name=context
        ):
            raise HTTPException(status_code=400, detail=f"{firewall_hostname} ({context}) is not ACTIVE")
    else:
        if not failOver(
            firewallIP, 
            username="amishra11", 
            password="Dru56%Pty7", 
            secret="Dru56%Pty7"
        ):
            raise HTTPException(status_code=400, detail=f"{firewall_hostname} is not ACTIVE")

    from itertools import product
    source_ips = [ip.strip() for ip in form_data.get("source_ip", "").split() if ip.strip()]
    dest_ips = [ip.strip() for ip in form_data.get("dest_ip", "").split() if ip.strip()]

    src_ip_list = source_ips or [None]
    dst_ip_list = dest_ips or [None]
    created_rule = []
    for index, (src_ip, dst_ip) in enumerate(product(src_ip_list, dst_ip_list)):
        new_rule = FirewallRule(
            itsr_number=form_data.get("itsr_number"),
            email=form_data.get("email"),
            source_ip=src_ip,
            dest_ip=dst_ip,
            multiple_ports=form_data.get("multiple_ports"),
            port_range_start=form_data.get("port_range_start"),
            port_range_end=form_data.get("port_range_end"),
            protocol=form_data.get("protocol"),
            ports=int(form_data.get("ports", 0)),
            Firewall=firewall_hostname,
            pre_status="Added to queue",
            post_status="Pending",
            final_status="Pending",
            created_by="admin",
            firewallIP=firewallIP,
            context=context
        )

        print(f"Entry {index + 1}")
        print(f"Source IP: {new_rule.source_ip}")
        print(f"Destination IP: {new_rule.dest_ip}")
        print("-" * 50)

        db.add(new_rule)
        created_rule.append(new_rule)
    
    db.flush()
    for rule in created_rule:
        checkInterface.update_firewall_interfaces_for_rule(
            rule=rule,
            username="amishra11",
            password="Dru56%Pty7",
            secret="Dru56%Pty7",
            db=db
        )
    db.commit()
    return {"message": "Firewall rules submitted successfully!"}

@app.get("/get-rules/{itsr_number}")
async def get_rules(itsr_number: str, db: Session = Depends(get_database)):
    rules = db.query(FirewallRule).filter(FirewallRule.itsr_number == itsr_number).all()
    if not rules:
        return {"rules": [], "message": "No rules found for this ITSR number"}
    
    # Fetch risks for fallback prefix matching
    risks = db.query(Risk).all()
    
    # Prepare the response
    rule_list = []
    for rule in rules:
        # Start with the Risk_Description from itsr_rules
        matched_risk_description = rule.Risk_Description or ""
        
        # If Risk_Description is not set, fall back to prefix matching
        if not matched_risk_description:
            for risk in risks:
                rule_source_ip = rule.source_ip.strip() if rule.source_ip else ""
                rule_dest_ip = rule.dest_ip.strip() if rule.dest_ip else ""
                risk_src_ip = risk.Src_ip.strip() if risk.Src_ip else ""
                risk_dst_ip = risk.Dst_IP.strip() if risk.Dst_IP else ""
                
                if (
                    (rule_source_ip and (rule_source_ip.startswith(risk_src_ip) or rule_source_ip.startswith(risk_dst_ip)))
                    and
                    (rule_dest_ip and (rule_dest_ip.startswith(risk_src_ip) or rule_dest_ip.startswith(risk_dst_ip)))
                ):
                    matched_risk_description = risk.Risk_Description
                    break
        
        rule_list.append({
            "itsr_number": rule.itsr_number,
            "source_ip": rule.source_ip,
            "dest_ip": rule.dest_ip,
            "multiple_ports": rule.multiple_ports or "",
            "Firewall": rule.Firewall,
            "inLine": rule.inLine or "",
            "Action": rule.Action or "",
            "pre_status": rule.pre_status,
            "post_status": rule.post_status,
            "post_action": rule.post_action or "",
            "post_reason": rule.post_reason or "",
            "email": rule.email,
            "port_range_start": rule.port_range_start,
            "port_range_end": rule.port_range_end,
            "protocol": rule.protocol,
            "final_status": rule.final_status,
            "matched_Risk_Description": matched_risk_description
        })
    
    return {
        "rules": rule_list,
        "message": f"{len(rules)} rule(s) found"
    }