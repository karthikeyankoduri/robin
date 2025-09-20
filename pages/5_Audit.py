import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from utils.db import get_db_session, AuditLog, Case
from utils.security import check_authentication, log_audit_event
import plotly.express as px
import plotly.graph_objects as go

st.set_page_config(
    page_title="Audit - Robin",
    page_icon="📋",
    layout="wide"
)

def main():
    st.title("📋 Audit & Chain of Custody")
    st.markdown("Complete audit trail and chain of custody tracking for forensic integrity")
    
    if not check_authentication():
        return
    
    # Audit dashboard tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "🔍 Audit Logs", "📊 Activity Overview", "🔒 Chain of Custody", "⚠️ Security Events"
    ])
    
    with tab1:
        display_audit_logs()
    
    with tab2:
        display_activity_overview()
    
    with tab3:
        display_chain_of_custody()
    
    with tab4:
        display_security_events()

def display_audit_logs():
    """Display comprehensive audit logs"""
    st.markdown("### Audit Log Viewer")
    
    # Filters
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        date_filter = st.selectbox(
            "Time Period",
            ["All Time", "Today", "Last 7 Days", "Last 30 Days", "Custom Range"]
        )
    
    with col2:
        action_filter = st.selectbox(
            "Action Type",
            ["All Actions", "FILE_UPLOADED", "CASE_CREATED", "AI_ANALYSIS", "SEARCH_PERFORMED", "DATA_EXPORTED", "LOGIN", "LOGOUT"]
        )
    
    with col3:
        user_filter = st.text_input("User Filter", placeholder="Enter username")
    
    with col4:
        case_filter = st.selectbox("Case Filter", get_case_options())
    
    # Custom date range
    if date_filter == "Custom Range":
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input("Start Date")
        with col2:
            end_date = st.date_input("End Date")
    else:
        start_date, end_date = get_date_range(date_filter)
    
    # Load and display audit logs
    try:
        session = get_db_session()
        logs = query_audit_logs(session, start_date, end_date, action_filter, user_filter, case_filter)
        
        if logs:
            display_audit_table(logs)
            
            # Export options
            st.markdown("### Export Audit Logs")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if st.button("📊 Export to CSV"):
                    export_audit_logs_csv(logs)
            
            with col2:
                if st.button("📄 Generate Audit Report"):
                    generate_audit_report(logs)
            
            with col3:
                if st.button("🔍 Detailed Analysis"):
                    display_detailed_audit_analysis(logs)
        else:
            st.info("No audit logs found for the selected criteria.")
        
        session.close()
        
    except Exception as e:
        st.error(f"Error loading audit logs: {str(e)}")

def display_activity_overview():
    """Display activity overview and statistics"""
    st.markdown("### Activity Overview")
    
    try:
        session = get_db_session()
        
        # Activity metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_events = session.query(AuditLog).count()
            st.metric("Total Events", total_events)
        
        with col2:
            today_events = session.query(AuditLog).filter(
                AuditLog.timestamp >= datetime.now().date()
            ).count()
            st.metric("Today's Events", today_events)
        
        with col3:
            unique_users = session.query(AuditLog.user_id).distinct().count()
            st.metric("Active Users", unique_users)
        
        with col4:
            unique_cases = session.query(AuditLog.case_id).distinct().count()
            st.metric("Active Cases", unique_cases)
        
        # Activity timeline chart
        st.markdown("#### Activity Timeline")
        timeline_data = get_activity_timeline_data(session)
        
        if timeline_data:
            df = pd.DataFrame(timeline_data)
            fig = px.line(
                df, x='date', y='count',
                title="Daily Activity Timeline",
                labels={'count': 'Number of Events', 'date': 'Date'}
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Activity by action type
        st.markdown("#### Activity by Type")
        action_data = get_activity_by_action(session)
        
        if action_data:
            fig = px.pie(
                values=list(action_data.values()),
                names=list(action_data.keys()),
                title="Activity Distribution by Action Type"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Most active users
        st.markdown("#### Most Active Users")
        user_activity = get_user_activity_stats(session)
        
        if user_activity:
            df = pd.DataFrame(user_activity)
            st.dataframe(df, use_container_width=True)
        
        session.close()
        
    except Exception as e:
        st.error(f"Error loading activity overview: {str(e)}")

def display_chain_of_custody():
    """Display chain of custody tracking"""
    st.markdown("### Chain of Custody Tracking")
    
    # Case selection for chain of custody
    session = get_db_session()
    try:
        cases = session.query(Case).all()
        if not cases:
            st.warning("No cases found.")
            return
        
        case_options = {f"{case.name} (ID: {case.id})": case.id for case in cases}
        selected_case = st.selectbox("Select Case for Chain of Custody", options=list(case_options.keys()))
        case_id = case_options[selected_case]
        
        # Get chain of custody for selected case
        custody_chain = get_custody_chain(session, case_id)
        
        if custody_chain:
            st.markdown("#### Evidence Chain of Custody")
            display_custody_timeline(custody_chain)
            
            # Custody verification
            st.markdown("#### Custody Verification")
            verify_custody_integrity(custody_chain)
            
            # Add custody event
            st.markdown("#### Add Custody Event")
            add_custody_event_form(session, case_id)
        else:
            st.info("No custody events found for this case.")
        
        session.close()
        
    except Exception as e:
        st.error(f"Error loading chain of custody: {str(e)}")

def display_security_events():
    """Display security-related events and alerts"""
    st.markdown("### Security Events & Alerts")
    
    try:
        session = get_db_session()
        
        # Security event filters
        col1, col2 = st.columns(2)
        
        with col1:
            security_level = st.selectbox(
                "Security Level",
                ["All Levels", "Critical", "High", "Medium", "Low"]
            )
        
        with col2:
            event_type = st.selectbox(
                "Event Type",
                ["All Events", "Failed Login", "Unauthorized Access", "Data Export", "File Deletion", "System Changes"]
            )
        
        # Get security events
        security_events = get_security_events(session, security_level, event_type)
        
        if security_events:
            # Security alerts summary
            display_security_alerts_summary(security_events)
            
            # Security events table
            st.markdown("#### Security Events")
            display_security_events_table(security_events)
            
            # Security trends
            st.markdown("#### Security Trends")
            display_security_trends(security_events)
        else:
            st.success("No security events found.")
        
        session.close()
        
    except Exception as e:
        st.error(f"Error loading security events: {str(e)}")

# Helper functions

def get_case_options():
    """Get case options for filtering"""
    try:
        session = get_db_session()
        cases = session.query(Case).all()
        options = ["All Cases"] + [f"{case.name} (ID: {case.id})" for case in cases]
        session.close()
        return options
    except:
        return ["All Cases"]

def get_date_range(filter_type):
    """Get date range based on filter type"""
    if filter_type == "Today":
        start_date = datetime.now().date()
        end_date = datetime.now().date()
    elif filter_type == "Last 7 Days":
        start_date = (datetime.now() - timedelta(days=7)).date()
        end_date = datetime.now().date()
    elif filter_type == "Last 30 Days":
        start_date = (datetime.now() - timedelta(days=30)).date()
        end_date = datetime.now().date()
    else:
        start_date = None
        end_date = None
    
    return start_date, end_date

def query_audit_logs(session, start_date, end_date, action_filter, user_filter, case_filter):
    """Query audit logs with filters"""
    query = session.query(AuditLog)
    
    # Apply filters
    if start_date:
        query = query.filter(AuditLog.timestamp >= start_date)
    if end_date:
        query = query.filter(AuditLog.timestamp <= end_date)
    if action_filter != "All Actions":
        query = query.filter(AuditLog.action == action_filter)
    if user_filter:
        query = query.filter(AuditLog.user_id.ilike(f"%{user_filter}%"))
    if case_filter != "All Cases":
        # Extract case ID from filter string
        case_id = int(case_filter.split("ID: ")[1].rstrip(")"))
        query = query.filter(AuditLog.case_id == case_id)
    
    return query.order_by(AuditLog.timestamp.desc()).all()

def display_audit_table(logs):
    """Display audit logs in a table"""
    audit_data = []
    for log in logs:
        audit_data.append({
            'Timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'User': log.user_id,
            'Action': log.action,
            'Case ID': log.case_id,
            'Details': log.details[:100] + "..." if len(log.details) > 100 else log.details,
            'IP Address': log.ip_address,
            'User Agent': log.user_agent[:50] + "..." if log.user_agent and len(log.user_agent) > 50 else log.user_agent
        })
    
    df = pd.DataFrame(audit_data)
    st.dataframe(df, use_container_width=True)
    
    # Expandable details for full information
    st.markdown("#### Detailed View")
    selected_log = st.selectbox("Select log for details", range(len(logs)), format_func=lambda x: f"Log {x+1}: {logs[x].action}")
    
    if selected_log is not None:
        log = logs[selected_log]
        with st.expander("Full Log Details"):
            st.json({
                'id': log.id,
                'timestamp': str(log.timestamp),
                'user_id': log.user_id,
                'action': log.action,
                'case_id': log.case_id,
                'details': log.details,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent
            })

def get_activity_timeline_data(session):
    """Get activity timeline data for charts"""
    # This would involve complex SQL queries to aggregate data by date
    # For now, return sample structure
    try:
        # Query to get daily activity counts
        from sqlalchemy import func
        results = session.query(
            func.date(AuditLog.timestamp).label('date'),
            func.count(AuditLog.id).label('count')
        ).group_by(func.date(AuditLog.timestamp)).all()
        
        return [{'date': result.date, 'count': result.count} for result in results]
    except:
        return []

def get_activity_by_action(session):
    """Get activity counts by action type"""
    try:
        from sqlalchemy import func
        results = session.query(
            AuditLog.action,
            func.count(AuditLog.id).label('count')
        ).group_by(AuditLog.action).all()
        
        return {result.action: result.count for result in results}
    except:
        return {}

def get_user_activity_stats(session):
    """Get user activity statistics"""
    try:
        from sqlalchemy import func
        results = session.query(
            AuditLog.user_id,
            func.count(AuditLog.id).label('total_actions'),
            func.max(AuditLog.timestamp).label('last_activity')
        ).group_by(AuditLog.user_id).order_by(func.count(AuditLog.id).desc()).limit(10).all()
        
        return [
            {
                'User': result.user_id,
                'Total Actions': result.total_actions,
                'Last Activity': result.last_activity.strftime('%Y-%m-%d %H:%M:%S') if result.last_activity else 'N/A'
            }
            for result in results
        ]
    except:
        return []

def get_custody_chain(session, case_id):
    """Get chain of custody events for a case"""
    custody_actions = ['FILE_UPLOADED', 'DATA_EXPORTED', 'EVIDENCE_ACCESSED', 'CASE_CREATED', 'CASE_CLOSED']
    
    events = session.query(AuditLog).filter(
        AuditLog.case_id == case_id,
        AuditLog.action.in_(custody_actions)
    ).order_by(AuditLog.timestamp).all()
    
    return events

def display_custody_timeline(custody_chain):
    """Display custody timeline visualization"""
    if not custody_chain:
        return
    
    # Create timeline data
    timeline_data = []
    for event in custody_chain:
        timeline_data.append({
            'Timestamp': event.timestamp,
            'Action': event.action,
            'User': event.user_id,
            'Details': event.details
        })
    
    df = pd.DataFrame(timeline_data)
    
    # Display as timeline chart
    fig = px.scatter(
        df, x='Timestamp', y='Action', 
        hover_data=['User', 'Details'],
        title="Chain of Custody Timeline"
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # Display as table
    st.dataframe(df, use_container_width=True)

def verify_custody_integrity(custody_chain):
    """Verify the integrity of the custody chain"""
    if not custody_chain:
        st.warning("No custody events to verify.")
        return
    
    # Check for gaps in custody
    gaps = []
    for i in range(1, len(custody_chain)):
        prev_event = custody_chain[i-1]
        curr_event = custody_chain[i]
        
        time_diff = curr_event.timestamp - prev_event.timestamp
        if time_diff.total_seconds() > 86400:  # More than 24 hours
            gaps.append({
                'from': prev_event.timestamp,
                'to': curr_event.timestamp,
                'duration': str(time_diff)
            })
    
    if gaps:
        st.warning(f"⚠️ Found {len(gaps)} potential gaps in custody chain:")
        for gap in gaps:
            st.error(f"Gap from {gap['from']} to {gap['to']} (Duration: {gap['duration']})")
    else:
        st.success("✅ Custody chain integrity verified - no significant gaps found.")

def add_custody_event_form(session, case_id):
    """Form to add a new custody event"""
    with st.form("add_custody_event"):
        col1, col2 = st.columns(2)
        
        with col1:
            event_type = st.selectbox(
                "Event Type",
                ["EVIDENCE_ACCESSED", "EVIDENCE_TRANSFERRED", "ANALYSIS_PERFORMED", "EVIDENCE_SECURED"]
            )
        
        with col2:
            handler = st.text_input("Handler/Investigator", value=st.session_state.get('username', ''))
        
        details = st.text_area("Event Details", placeholder="Describe the custody event...")
        
        if st.form_submit_button("Add Custody Event"):
            if event_type and handler and details:
                try:
                    log_audit_event(session, handler, event_type, details, case_id)
                    session.commit()
                    st.success("Custody event added successfully!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to add custody event: {str(e)}")
            else:
                st.error("Please fill in all required fields.")

def get_security_events(session, security_level, event_type):
    """Get security events based on filters"""
    # Define security-related actions
    security_actions = ['LOGIN_FAILED', 'UNAUTHORIZED_ACCESS', 'DATA_EXPORT', 'FILE_DELETION', 'SYSTEM_CHANGE']
    
    query = session.query(AuditLog).filter(AuditLog.action.in_(security_actions))
    
    # Apply filters (simplified for demo)
    if event_type != "All Events":
        # Map event types to actions
        action_mapping = {
            "Failed Login": "LOGIN_FAILED",
            "Unauthorized Access": "UNAUTHORIZED_ACCESS",
            "Data Export": "DATA_EXPORT",
            "File Deletion": "FILE_DELETION",
            "System Changes": "SYSTEM_CHANGE"
        }
        if event_type in action_mapping:
            query = query.filter(AuditLog.action == action_mapping[event_type])
    
    return query.order_by(AuditLog.timestamp.desc()).all()

def display_security_alerts_summary(security_events):
    """Display security alerts summary"""
    if not security_events:
        return
    
    # Count events by severity (simplified)
    critical_count = len([e for e in security_events if 'FAILED' in e.action or 'UNAUTHORIZED' in e.action])
    warning_count = len([e for e in security_events if 'EXPORT' in e.action])
    info_count = len(security_events) - critical_count - warning_count
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Critical Alerts", critical_count, delta=None if critical_count == 0 else f"+{critical_count}")
    
    with col2:
        st.metric("Warnings", warning_count)
    
    with col3:
        st.metric("Info Events", info_count)

def display_security_events_table(security_events):
    """Display security events in a table"""
    if not security_events:
        return
    
    security_data = []
    for event in security_events:
        severity = "Critical" if 'FAILED' in event.action or 'UNAUTHORIZED' in event.action else "Warning"
        
        security_data.append({
            'Timestamp': event.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'Severity': severity,
            'Event Type': event.action,
            'User': event.user_id,
            'IP Address': event.ip_address,
            'Details': event.details[:100] + "..." if len(event.details) > 100 else event.details
        })
    
    df = pd.DataFrame(security_data)
    
    # Color code by severity
    def color_severity(val):
        if val == 'Critical':
            return 'background-color: #ffebee'
        elif val == 'Warning':
            return 'background-color: #fff3e0'
        return ''
    
    styled_df = df.style.applymap(color_severity, subset=['Severity'])
    st.dataframe(styled_df, use_container_width=True)

def display_security_trends(security_events):
    """Display security trends and patterns"""
    if not security_events:
        return
    
    # Analyze trends (simplified)
    daily_counts = {}
    for event in security_events:
        date = event.timestamp.date()
        daily_counts[date] = daily_counts.get(date, 0) + 1
    
    if daily_counts:
        df = pd.DataFrame(list(daily_counts.items()), columns=['Date', 'Count'])
        fig = px.line(df, x='Date', y='Count', title="Security Events Trend")
        st.plotly_chart(fig, use_container_width=True)

def export_audit_logs_csv(logs):
    """Export audit logs to CSV"""
    audit_data = []
    for log in logs:
        audit_data.append({
            'ID': log.id,
            'Timestamp': log.timestamp,
            'User': log.user_id,
            'Action': log.action,
            'Case ID': log.case_id,
            'Details': log.details,
            'IP Address': log.ip_address,
            'User Agent': log.user_agent
        })
    
    df = pd.DataFrame(audit_data)
    csv = df.to_csv(index=False)
    
    st.download_button(
        label="Download Audit Logs CSV",
        data=csv,
        file_name=f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv"
    )

def generate_audit_report(logs):
    """Generate comprehensive audit report"""
    # This would generate a detailed audit report
    report_content = f"""# Audit Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
Total Events: {len(logs)}
Date Range: {logs[-1].timestamp if logs else 'N/A'} to {logs[0].timestamp if logs else 'N/A'}

## Event Breakdown
[This would include detailed analysis of the audit logs]
"""
    
    st.download_button(
        label="Download Audit Report",
        data=report_content,
        file_name=f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
        mime="text/markdown"
    )

def display_detailed_audit_analysis(logs):
    """Display detailed audit analysis"""
    st.markdown("#### Detailed Audit Analysis")
    
    if not logs:
        st.info("No logs to analyze.")
        return
    
    # User activity analysis
    user_stats = {}
    action_stats = {}
    
    for log in logs:
        user_stats[log.user_id] = user_stats.get(log.user_id, 0) + 1
        action_stats[log.action] = action_stats.get(log.action, 0) + 1
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**User Activity Distribution**")
        if user_stats:
            fig = px.bar(
                x=list(user_stats.keys()),
                y=list(user_stats.values()),
                title="Events by User"
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("**Action Type Distribution**")
        if action_stats:
            fig = px.bar(
                x=list(action_stats.keys()),
                y=list(action_stats.values()),
                title="Events by Action Type"
            )
            st.plotly_chart(fig, use_container_width=True)

if __name__ == "__main__":
    main()
