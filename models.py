from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Date  # Updated: Added Date import
from database import Base
import datetime
from sqlalchemy.orm import relationship

# Updated: Added Risk model for the new Risk table
class Risk(Base):
    __tablename__ = "risk"
    
    id = Column(Integer, primary_key=True, index=True)
    Src_ip = Column(String(45))  # Supports IPv4 and IPv6
    Dst_IP = Column(String(45))
    Risk_Description = Column(Text)

# Model for accessing it with UI
class FirewallRule(Base):
    __tablename__ = "itsr_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    itsr_number = Column(String(50), index=True)
    email = Column(String(100))
    source_ip = Column(Text)
    dest_ip = Column(Text)
    src_interface=Column(Text)
    dst_interface =Column(Text)
    src_access_group = Column(Text)
    dst_access_group = Column(Text)
    multiple_ports = Column(String(50))
    port_range_start = Column(Text, nullable=False)
    port_range_end = Column(Text, nullable=False)
    protocol = Column(String(20))
    ports = Column(String(5000))
    context = Column(Text)
    pre_status = Column(String(50))
    post_status = Column(String(50))
    final_status = Column(String(50))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    created_by = Column(String(20))
    Firewall = Column(String(100))
    firewallIP = Column(String(100))
    inLine = Column(String(100))
    Action = Column(String(10))
    Reason = Column(Text)
    post_action = Column(Text)
    post_reason = Column(Text)
    # Updated: Added new columns for itsr_rules
    Risk_Description = Column(Text)
    Security_Exception_number = Column(String(50))
    Security_Exception_expiry_date = Column(Date)

class FirewallList(Base):
    __tablename__ = "firewall_list"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(20))
    firewall_hostname = Column(String(100))
    model = Column(String(20))
    context_name = Column(String(20))