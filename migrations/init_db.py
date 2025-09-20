"""
Database initialization migration for Robin Forensic Analysis Tool
This script sets up the initial database schema and default data
"""

import os
import sys
from datetime import datetime
import logging

# Add the parent directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.db import init_database, get_db_session, User, Case, AuditLog
from utils.security import hash_password, log_audit_event

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_database_schema():
    """Create all database tables and indexes"""
    try:
        logger.info("Creating database schema...")
        init_database()
        logger.info("Database schema created successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to create database schema: {e}")
        return False

def create_default_users():
    """Create default system users"""
    try:
        logger.info("Creating default users...")
        session = get_db_session()
        
        # Check if admin user already exists
        existing_admin = session.query(User).filter(User.username == "admin").first()
        if existing_admin:
            logger.info("Admin user already exists")
            session.close()
            return True
        
        # Create admin user
        admin_user = User(
            username="admin",
            email="admin@robin.local",
            hashed_password=hash_password("admin123"),
            full_name="System Administrator",
            role="ADMIN",
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        session.add(admin_user)
        
        # Create default investigator user
        investigator_user = User(
            username="investigator",
            email="investigator@robin.local",
            hashed_password=hash_password("investigator123"),
            full_name="Default Investigator",
            role="INVESTIGATOR",
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        session.add(investigator_user)
        
        # Create read-only viewer user
        viewer_user = User(
            username="viewer",
            email="viewer@robin.local",
            hashed_password=hash_password("viewer123"),
            full_name="Default Viewer",
            role="VIEWER",
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        session.add(viewer_user)
        
        session.commit()
        
        # Log user creation
        log_audit_event(
            session,
            "system",
            "SYSTEM_INIT",
            "Default users created during system initialization"
        )
        
        session.commit()
        session.close()
        
        logger.info("Default users created successfully")
        logger.info("Default credentials:")
        logger.info("  Admin: admin / admin123")
        logger.info("  Investigator: investigator / investigator123")
        logger.info("  Viewer: viewer / viewer123")
        
        return True
    
    except Exception as e:
        logger.error(f"Failed to create default users: {e}")
        return False

def create_sample_case():
    """Create a sample case for demonstration purposes"""
    try:
        logger.info("Creating sample case...")
        session = get_db_session()
        
        # Check if sample case already exists
        existing_case = session.query(Case).filter(Case.name == "Sample Investigation").first()
        if existing_case:
            logger.info("Sample case already exists")
            session.close()
            return True
        
        # Create sample case
        sample_case = Case(
            name="Sample Investigation",
            description="This is a sample case created during system initialization for demonstration purposes.",
            investigator="System",
            created_at=datetime.utcnow(),
            status="ACTIVE"
        )
        
        session.add(sample_case)
        session.commit()
        
        # Log case creation
        log_audit_event(
            session,
            "system",
            "CASE_CREATED",
            f"Sample case created during system initialization: {sample_case.name}",
            case_id=sample_case.id
        )
        
        session.commit()
        session.close()
        
        logger.info("Sample case created successfully")
        return True
    
    except Exception as e:
        logger.error(f"Failed to create sample case: {e}")
        return False

def setup_search_indexes():
    """Set up database indexes for optimal search performance"""
    try:
        logger.info("Setting up search indexes...")
        session = get_db_session()
        
        # Note: Index creation is handled in the model definitions
        # This function could be extended to create additional
        # database-specific indexes or full-text search indexes
        
        # For PostgreSQL, you might add:
        # session.execute("CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_chat_content_gin ON chat_messages USING gin(to_tsvector('english', content));")
        
        # For SQLite with FTS, you might add:
        # session.execute("CREATE VIRTUAL TABLE IF NOT EXISTS chat_messages_fts USING fts5(content, sender);")
        
        session.close()
        logger.info("Search indexes set up successfully")
        return True
    
    except Exception as e:
        logger.error(f"Failed to set up search indexes: {e}")
        return False

def verify_database_setup():
    """Verify that the database is set up correctly"""
    try:
        logger.info("Verifying database setup...")
        session = get_db_session()
        
        # Check that tables exist and are accessible
        user_count = session.query(User).count()
        case_count = session.query(Case).count()
        audit_count = session.query(AuditLog).count()
        
        logger.info(f"Database verification results:")
        logger.info(f"  Users: {user_count}")
        logger.info(f"  Cases: {case_count}")
        logger.info(f"  Audit logs: {audit_count}")
        
        session.close()
        
        if user_count > 0:
            logger.info("Database setup verification successful")
            return True
        else:
            logger.error("Database setup verification failed - no users found")
            return False
    
    except Exception as e:
        logger.error(f"Database verification failed: {e}")
        return False

def create_configuration_file():
    """Create default configuration file if it doesn't exist"""
    try:
        config_dir = ".streamlit"
        config_file = os.path.join(config_dir, "config.toml")
        
        if os.path.exists(config_file):
            logger.info("Streamlit configuration file already exists")
            return True
        
        # Create .streamlit directory if it doesn't exist
        os.makedirs(config_dir, exist_ok=True)
        
        # Create default configuration
        config_content = """[server]
headless = true
address = "0.0.0.0"
port = 5000

[theme]
base = "light"

[browser]
gatherUsageStats = false
"""
        
        with open(config_file, 'w') as f:
            f.write(config_content)
        
        logger.info("Streamlit configuration file created")
        return True
    
    except Exception as e:
        logger.error(f"Failed to create configuration file: {e}")
        return False

def log_initialization_complete():
    """Log that initialization is complete"""
    try:
        session = get_db_session()
        
        log_audit_event(
            session,
            "system",
            "SYSTEM_INIT_COMPLETE",
            "Robin Forensic Analysis Tool initialization completed successfully"
        )
        
        session.commit()
        session.close()
        
        logger.info("System initialization logged successfully")
        return True
    
    except Exception as e:
        logger.error(f"Failed to log initialization: {e}")
        return False

def main():
    """Main initialization function"""
    logger.info("Starting Robin Forensic Analysis Tool database initialization...")
    
    success = True
    
    # Step 1: Create database schema
    if not create_database_schema():
        success = False
    
    # Step 2: Create default users
    if success and not create_default_users():
        success = False
    
    # Step 3: Create sample case
    if success and not create_sample_case():
        success = False
    
    # Step 4: Set up search indexes
    if success and not setup_search_indexes():
        success = False
    
    # Step 5: Create configuration file
    if success and not create_configuration_file():
        success = False
    
    # Step 6: Verify database setup
    if success and not verify_database_setup():
        success = False
    
    # Step 7: Log completion
    if success and not log_initialization_complete():
        success = False
    
    if success:
        logger.info("✅ Robin Forensic Analysis Tool initialization completed successfully!")
        logger.info("")
        logger.info("🚀 You can now start the application with:")
        logger.info("   streamlit run Home.py")
        logger.info("")
        logger.info("🔐 Default login credentials:")
        logger.info("   Admin: admin / admin123")
        logger.info("   Investigator: investigator / investigator123")
        logger.info("   Viewer: viewer / viewer123")
        logger.info("")
        logger.info("⚠️  Remember to change default passwords in production!")
    else:
        logger.error("❌ Robin Forensic Analysis Tool initialization failed!")
        logger.error("Please check the error messages above and try again.")
        sys.exit(1)

if __name__ == "__main__":
    main()
