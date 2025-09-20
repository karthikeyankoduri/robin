import streamlit as st
import os
from utils.db import init_database, get_db_session
from utils.security import check_authentication
import pandas as pd

# Configure page
st.set_page_config(
    page_title="Robin - AI Forensic Analysis Tool",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded"
)

def main():
    st.title("🕵️ Robin - AI Forensic Analysis Tool")
    st.markdown("### Universal Forensic Data Report (UFDR) Analysis Platform")
    
    # Initialize database on first run
    if 'db_initialized' not in st.session_state:
        try:
            init_database()
            st.session_state.db_initialized = True
            st.success("Database initialized successfully!")
        except Exception as e:
            st.error(f"Database initialization failed: {str(e)}")
            return
    
    # Authentication check
    if not check_authentication():
        return
    
    # Dashboard overview
    col1, col2, col3, col4 = st.columns(4)
    
    try:
        session = get_db_session()
        
        # Get statistics from database
        with col1:
            st.metric("Total Cases", get_cases_count(session))
        
        with col2:
            st.metric("Chat Messages", get_messages_count(session))
        
        with col3:
            st.metric("Call Records", get_calls_count(session))
        
        with col4:
            st.metric("Contacts", get_contacts_count(session))
        
        session.close()
    except Exception as e:
        st.error(f"Error loading dashboard statistics: {str(e)}")
    
    # Quick actions
    st.markdown("### Quick Actions")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📁 Upload UFDR Files", use_container_width=True):
            st.switch_page("pages/1_Upload.py")
    
    with col2:
        if st.button("🔍 Search Data", use_container_width=True):
            st.switch_page("pages/2_Search.py")
    
    with col3:
        if st.button("🤖 AI Analysis", use_container_width=True):
            st.switch_page("pages/4_AI_Analysis.py")
    
    # Recent activity
    st.markdown("### Recent Activity")
    try:
        session = get_db_session()
        recent_logs = get_recent_audit_logs(session, limit=10)
        if recent_logs:
            df = pd.DataFrame([
                {
                    "Timestamp": log.timestamp,
                    "Action": log.action,
                    "User": log.user_id,
                    "Details": log.details[:100] + "..." if len(log.details) > 100 else log.details
                }
                for log in recent_logs
            ])
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No recent activity found.")
        session.close()
    except Exception as e:
        st.error(f"Error loading recent activity: {str(e)}")

def get_cases_count(session):
    from utils.db import Case
    try:
        return session.query(Case).count()
    except:
        return 0

def get_messages_count(session):
    from utils.db import ChatMessage
    try:
        return session.query(ChatMessage).count()
    except:
        return 0

def get_calls_count(session):
    from utils.db import Call
    try:
        return session.query(Call).count()
    except:
        return 0

def get_contacts_count(session):
    from utils.db import Contact
    try:
        return session.query(Contact).count()
    except:
        return 0

def get_recent_audit_logs(session, limit=10):
    from utils.db import AuditLog
    try:
        return session.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    except:
        return []

if __name__ == "__main__":
    main()
