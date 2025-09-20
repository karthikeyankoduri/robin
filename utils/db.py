import os
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import logging

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///robin_forensics.db')

# Create engine and session
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Case(Base):
    """Case model for forensic investigations"""
    __tablename__ = "cases"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    investigator = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(String(50), default="ACTIVE")
    
    # Relationships
    chat_messages = relationship("ChatMessage", back_populates="case", cascade="all, delete-orphan")
    calls = relationship("Call", back_populates="case", cascade="all, delete-orphan")
    contacts = relationship("Contact", back_populates="case", cascade="all, delete-orphan")
    media_files = relationship("Media", back_populates="case", cascade="all, delete-orphan")
    locations = relationship("Location", back_populates="case", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="case", cascade="all, delete-orphan")

class ChatMessage(Base):
    """Chat message model for storing text communications"""
    __tablename__ = "chat_messages"
    
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    chat_id = Column(String(255), index=True)  # Conversation/thread identifier
    app_name = Column(String(100))  # WhatsApp, SMS, Telegram, etc.
    sender = Column(String(255), index=True)
    recipient = Column(String(255), index=True)
    content = Column(Text)
    timestamp = Column(DateTime, index=True)
    direction = Column(String(20))  # INCOMING, OUTGOING
    message_type = Column(String(50))  # TEXT, IMAGE, VIDEO, AUDIO, DOCUMENT
    is_deleted = Column(Boolean, default=False)
    coordinates = Column(String(100))  # "lat,lng" format
    
    # Relationships
    case = relationship("Case", back_populates="chat_messages")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_chat_timestamp', 'case_id', 'timestamp'),
        Index('idx_chat_sender', 'case_id', 'sender'),
        Index('idx_chat_content', 'content'),  # For full-text search
    )

class Call(Base):
    """Call log model for storing voice call data"""
    __tablename__ = "calls"
    
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    phone_number = Column(String(50), index=True)
    contact_name = Column(String(255))
    call_type = Column(String(20))  # VOICE, VIDEO
    direction = Column(String(20))  # INCOMING, OUTGOING, MISSED
    timestamp = Column(DateTime, index=True)
    duration = Column(Integer)  # Duration in seconds
    coordinates = Column(String(100))  # "lat,lng" format
    cell_tower = Column(String(100))
    
    # Relationships
    case = relationship("Case", back_populates="calls")
    
    # Indexes
    __table_args__ = (
        Index('idx_call_timestamp', 'case_id', 'timestamp'),
        Index('idx_call_number', 'case_id', 'phone_number'),
    )

class Contact(Base):
    """Contact model for storing address book entries"""
    __tablename__ = "contacts"
    
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    name = Column(String(255), index=True)
    phone_numbers = Column(Text)  # JSON array of phone numbers
    emails = Column(Text)  # JSON array of email addresses
    organization = Column(String(255))
    notes = Column(Text)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    
    # Relationships
    case = relationship("Case", back_populates="contacts")
    
    # Indexes
    __table_args__ = (
        Index('idx_contact_name', 'case_id', 'name'),
    )

class Media(Base):
    """Media model for storing image/video/audio file metadata"""
    __tablename__ = "media"
    
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    file_name = Column(String(500))
    file_path = Column(String(1000))
    file_type = Column(String(50))  # IMAGE, VIDEO, AUDIO, DOCUMENT
    file_size = Column(Integer)
    hash_md5 = Column(String(32), index=True)
    hash_sha256 = Column(String(64), index=True)
    timestamp = Column(DateTime, index=True)
    coordinates = Column(String(100))  # From EXIF data
    camera_make = Column(String(100))
    camera_model = Column(String(100))
    exif_data = Column(Text)  # JSON string of EXIF data
    
    # Relationships
    case = relationship("Case", back_populates="media_files")
    
    # Indexes
    __table_args__ = (
        Index('idx_media_timestamp', 'case_id', 'timestamp'),
        Index('idx_media_type', 'case_id', 'file_type'),
        Index('idx_media_hash', 'hash_md5', 'hash_sha256'),
    )

class Location(Base):
    """Location model for storing GPS and location data"""
    __tablename__ = "locations"
    
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    timestamp = Column(DateTime, index=True)
    latitude = Column(Float)
    longitude = Column(Float)
    altitude = Column(Float)
    accuracy = Column(Float)  # GPS accuracy in meters
    source = Column(String(50))  # GPS, WIFI, CELL_TOWER, MANUAL
    activity = Column(String(50))  # WALKING, DRIVING, STATIONARY, etc.
    
    # Relationships
    case = relationship("Case", back_populates="locations")
    
    # Indexes
    __table_args__ = (
        Index('idx_location_timestamp', 'case_id', 'timestamp'),
        Index('idx_location_coords', 'latitude', 'longitude'),
    )

class AuditLog(Base):
    """Audit log model for tracking all system activities"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    user_id = Column(String(255), nullable=False, index=True)
    action = Column(String(100), nullable=False, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True, index=True)
    details = Column(Text)
    ip_address = Column(String(45))  # IPv6 compatible
    user_agent = Column(Text)
    session_id = Column(String(255))
    
    # Relationships
    case = relationship("Case", back_populates="audit_logs")
    
    # Indexes
    __table_args__ = (
        Index('idx_audit_timestamp', 'timestamp'),
        Index('idx_audit_user_action', 'user_id', 'action'),
    )

class User(Base):
    """User model for authentication and authorization"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(String(50), default="INVESTIGATOR")  # ADMIN, INVESTIGATOR, VIEWER
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)

class Entity(Base):
    """Entity model for storing extracted named entities"""
    __tablename__ = "entities"
    
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    entity_text = Column(String(500), nullable=False)
    entity_type = Column(String(50), nullable=False, index=True)  # PERSON, ORG, GPE, etc.
    confidence = Column(Float)
    source_table = Column(String(50))  # chat_messages, calls, etc.
    source_id = Column(Integer)
    context = Column(Text)  # Surrounding text for context
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Indexes
    __table_args__ = (
        Index('idx_entity_case_type', 'case_id', 'entity_type'),
        Index('idx_entity_text', 'entity_text'),
    )

def init_database():
    """Initialize the database and create all tables"""
    try:
        # Create all tables
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
        
        # Create default admin user if it doesn't exist
        session = get_db_session()
        try:
            from utils.security import hash_password
            
            existing_admin = session.query(User).filter(User.username == "admin").first()
            if not existing_admin:
                admin_user = User(
                    username="admin",
                    email="admin@robin.local",
                    hashed_password=hash_password("admin123"),
                    full_name="System Administrator",
                    role="ADMIN"
                )
                session.add(admin_user)
                session.commit()
                logger.info("Default admin user created")
        except Exception as e:
            logger.error(f"Error creating default admin user: {e}")
            session.rollback()
        finally:
            session.close()
            
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

def get_db_session():
    """Get a database session"""
    return SessionLocal()

def close_db_session(session):
    """Close a database session"""
    try:
        session.close()
    except Exception as e:
        logger.error(f"Error closing database session: {e}")

# Database utility functions

def get_case_by_id(case_id: int):
    """Get a case by ID"""
    session = get_db_session()
    try:
        case = session.query(Case).filter(Case.id == case_id).first()
        return case
    finally:
        session.close()

def get_messages_by_case(case_id: int, limit: int = 1000):
    """Get chat messages for a case"""
    session = get_db_session()
    try:
        messages = session.query(ChatMessage).filter(
            ChatMessage.case_id == case_id
        ).order_by(ChatMessage.timestamp.desc()).limit(limit).all()
        return messages
    finally:
        session.close()

def get_calls_by_case(case_id: int, limit: int = 1000):
    """Get call logs for a case"""
    session = get_db_session()
    try:
        calls = session.query(Call).filter(
            Call.case_id == case_id
        ).order_by(Call.timestamp.desc()).limit(limit).all()
        return calls
    finally:
        session.close()

def get_contacts_by_case(case_id: int):
    """Get contacts for a case"""
    session = get_db_session()
    try:
        contacts = session.query(Contact).filter(
            Contact.case_id == case_id
        ).all()
        return contacts
    finally:
        session.close()

def get_media_by_case(case_id: int, limit: int = 500):
    """Get media files for a case"""
    session = get_db_session()
    try:
        media = session.query(Media).filter(
            Media.case_id == case_id
        ).order_by(Media.timestamp.desc()).limit(limit).all()
        return media
    finally:
        session.close()

def get_locations_by_case(case_id: int, limit: int = 1000):
    """Get location data for a case"""
    session = get_db_session()
    try:
        locations = session.query(Location).filter(
            Location.case_id == case_id
        ).order_by(Location.timestamp.desc()).limit(limit).all()
        return locations
    finally:
        session.close()

def search_full_text(query: str, case_id: int = None, limit: int = 100):
    """Perform full-text search across all data types"""
    session = get_db_session()
    results = []
    
    try:
        # Search chat messages
        message_query = session.query(ChatMessage).filter(
            ChatMessage.content.ilike(f"%{query}%")
        )
        if case_id:
            message_query = message_query.filter(ChatMessage.case_id == case_id)
        
        messages = message_query.limit(limit).all()
        for msg in messages:
            results.append({
                'type': 'ChatMessage',
                'id': msg.id,
                'content': msg.content,
                'sender': msg.sender,
                'timestamp': msg.timestamp,
                'case_id': msg.case_id
            })
        
        # Search contacts
        contact_query = session.query(Contact).filter(
            Contact.name.ilike(f"%{query}%") | 
            Contact.notes.ilike(f"%{query}%")
        )
        if case_id:
            contact_query = contact_query.filter(Contact.case_id == case_id)
        
        contacts = contact_query.limit(limit).all()
        for contact in contacts:
            results.append({
                'type': 'Contact',
                'id': contact.id,
                'name': contact.name,
                'phone_numbers': contact.phone_numbers,
                'emails': contact.emails,
                'case_id': contact.case_id
            })
        
        # Search calls by phone number
        call_query = session.query(Call).filter(
            Call.phone_number.ilike(f"%{query}%") |
            Call.contact_name.ilike(f"%{query}%")
        )
        if case_id:
            call_query = call_query.filter(Call.case_id == case_id)
        
        calls = call_query.limit(limit).all()
        for call in calls:
            results.append({
                'type': 'Call',
                'id': call.id,
                'phone_number': call.phone_number,
                'contact_name': call.contact_name,
                'timestamp': call.timestamp,
                'direction': call.direction,
                'case_id': call.case_id
            })
        
    except Exception as e:
        logger.error(f"Full-text search error: {e}")
    finally:
        session.close()
    
    return results

# Health check function
def check_database_health():
    """Check database connectivity and health"""
    try:
        session = get_db_session()
        # Simple query to test connection
        session.execute("SELECT 1")
        session.close()
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False
