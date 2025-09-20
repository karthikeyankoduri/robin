import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import networkx as nx
from pyvis.network import Network
import tempfile
import os
from datetime import datetime, timedelta
from utils.db import get_db_session, Case
from utils.security import check_authentication
from utils.viz import (
    create_timeline_chart, create_contact_network, create_communication_heatmap,
    create_location_map, create_activity_chart, get_case_statistics
)

st.set_page_config(
    page_title="Visualization - Robin",
    page_icon="📈",
    layout="wide"
)

def main():
    st.title("📈 Data Visualization")
    st.markdown("Interactive visualizations and analytics for forensic data")
    
    if not check_authentication():
        return
    
    # Case selection
    session = get_db_session()
    try:
        cases = session.query(Case).all()
        if not cases:
            st.warning("No cases found. Please upload data first.")
            if st.button("Go to Upload"):
                st.switch_page("pages/1_Upload.py")
            return
        
        case_options = {f"{case.name} (ID: {case.id})": case.id for case in cases}
        selected_case_display = st.selectbox("Select Case for Visualization", options=list(case_options.keys()))
        case_id = case_options[selected_case_display]
        
    except Exception as e:
        st.error(f"Error loading cases: {str(e)}")
        return
    finally:
        session.close()
    
    # Visualization tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 Overview", "⏱️ Timeline", "🕸️ Network", "🗺️ Location", "📱 Activity"
    ])
    
    with tab1:
        display_overview(case_id)
    
    with tab2:
        display_timeline(case_id)
    
    with tab3:
        display_network_analysis(case_id)
    
    with tab4:
        display_location_analysis(case_id)
    
    with tab5:
        display_activity_analysis(case_id)

def display_overview(case_id):
    """Display case overview and statistics"""
    st.markdown("### Case Overview")
    
    try:
        # Get case statistics
        stats = get_case_statistics(case_id)
        
        # Display key metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Messages", stats.get('total_messages', 0))
        with col2:
            st.metric("Total Calls", stats.get('total_calls', 0))
        with col3:
            st.metric("Unique Contacts", stats.get('unique_contacts', 0))
        with col4:
            st.metric("Media Files", stats.get('total_media', 0))
        
        # Communication breakdown chart
        if stats.get('communication_breakdown'):
            st.markdown("#### Communication Breakdown")
            
            breakdown_data = stats['communication_breakdown']
            fig = px.pie(
                values=list(breakdown_data.values()),
                names=list(breakdown_data.keys()),
                title="Communication Types Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Daily activity chart
        if stats.get('daily_activity'):
            st.markdown("#### Daily Activity Pattern")
            
            activity_data = stats['daily_activity']
            df = pd.DataFrame(list(activity_data.items()), columns=['Date', 'Count'])
            df['Date'] = pd.to_datetime(df['Date'])
            
            fig = px.line(
                df, x='Date', y='Count',
                title="Daily Communication Activity",
                labels={'Count': 'Number of Communications'}
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Top contacts table
        if stats.get('top_contacts'):
            st.markdown("#### Most Active Contacts")
            
            contacts_df = pd.DataFrame(stats['top_contacts'])
            st.dataframe(contacts_df, use_container_width=True)
    
    except Exception as e:
        st.error(f"Error loading overview data: {str(e)}")

def display_timeline(case_id):
    """Display timeline visualization"""
    st.markdown("### Communication Timeline")
    
    # Timeline options
    col1, col2, col3 = st.columns(3)
    
    with col1:
        timeline_type = st.selectbox(
            "Timeline Type",
            ["All Communications", "Messages Only", "Calls Only", "Media Only"]
        )
    
    with col2:
        granularity = st.selectbox(
            "Time Granularity",
            ["Hour", "Day", "Week", "Month"]
        )
    
    with col3:
        date_range = st.selectbox(
            "Date Range",
            ["All Time", "Last 7 Days", "Last 30 Days", "Custom"]
        )
    
    # Custom date range picker
    if date_range == "Custom":
        col_start, col_end = st.columns(2)
        with col_start:
            start_date = st.date_input("Start Date")
        with col_end:
            end_date = st.date_input("End Date")
    else:
        start_date = None
        end_date = None
    
    try:
        # Create timeline chart
        timeline_fig = create_timeline_chart(
            case_id=case_id,
            timeline_type=timeline_type,
            granularity=granularity,
            start_date=start_date,
            end_date=end_date
        )
        
        if timeline_fig:
            st.plotly_chart(timeline_fig, use_container_width=True)
        else:
            st.info("No timeline data available for the selected criteria.")
    
    except Exception as e:
        st.error(f"Error creating timeline: {str(e)}")
    
    # Communication heatmap
    st.markdown("#### Communication Heatmap")
    
    try:
        heatmap_fig = create_communication_heatmap(case_id)
        if heatmap_fig:
            st.plotly_chart(heatmap_fig, use_container_width=True)
        else:
            st.info("No heatmap data available.")
    
    except Exception as e:
        st.error(f"Error creating heatmap: {str(e)}")

def display_network_analysis(case_id):
    """Display network analysis and contact relationships"""
    st.markdown("### Contact Network Analysis")
    
    # Network options
    col1, col2 = st.columns(2)
    
    with col1:
        network_type = st.selectbox(
            "Network Type",
            ["Communication Network", "Contact Groups", "Call Patterns"]
        )
    
    with col2:
        min_interactions = st.slider(
            "Minimum Interactions",
            min_value=1,
            max_value=50,
            value=5,
            help="Minimum number of interactions to include a contact"
        )
    
    try:
        # Create network graph
        network_html = create_contact_network(
            case_id=case_id,
            network_type=network_type,
            min_interactions=min_interactions
        )
        
        if network_html:
            # Display the interactive network
            st.components.v1.html(network_html, height=600)
            
            # Network statistics
            st.markdown("#### Network Statistics")
            
            # You would calculate these from the network data
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Nodes", "N/A")  # Replace with actual calculation
            with col2:
                st.metric("Total Edges", "N/A")  # Replace with actual calculation
            with col3:
                st.metric("Network Density", "N/A")  # Replace with actual calculation
        else:
            st.info("No network data available for visualization.")
    
    except Exception as e:
        st.error(f"Error creating network visualization: {str(e)}")
    
    # Most connected contacts
    st.markdown("#### Most Connected Contacts")
    
    try:
        # This would be implemented in the viz module
        # For now, show a placeholder
        st.info("Contact centrality analysis will be displayed here.")
    
    except Exception as e:
        st.error(f"Error analyzing contact connections: {str(e)}")

def display_location_analysis(case_id):
    """Display location-based visualizations"""
    st.markdown("### Location Analysis")
    
    # Location options
    col1, col2 = st.columns(2)
    
    with col1:
        location_source = st.selectbox(
            "Location Source",
            ["All Sources", "GPS Data", "Cell Tower", "WiFi", "Media EXIF"]
        )
    
    with col2:
        time_filter = st.selectbox(
            "Time Period",
            ["All Time", "Last 24 Hours", "Last Week", "Last Month"]
        )
    
    try:
        # Create location map
        location_map = create_location_map(
            case_id=case_id,
            source_filter=location_source,
            time_filter=time_filter
        )
        
        if location_map:
            st.plotly_chart(location_map, use_container_width=True)
        else:
            st.info("No location data available for mapping.")
    
    except Exception as e:
        st.error(f"Error creating location map: {str(e)}")
    
    # Location timeline
    st.markdown("#### Location Timeline")
    
    try:
        # Create location-over-time visualization
        st.info("Location timeline visualization will be displayed here.")
    
    except Exception as e:
        st.error(f"Error creating location timeline: {str(e)}")
    
    # Significant locations
    st.markdown("#### Significant Locations")
    
    try:
        # Show frequently visited locations
        st.info("Analysis of frequently visited locations will be displayed here.")
    
    except Exception as e:
        st.error(f"Error analyzing significant locations: {str(e)}")

def display_activity_analysis(case_id):
    """Display activity pattern analysis"""
    st.markdown("### Activity Pattern Analysis")
    
    # Activity options
    col1, col2 = st.columns(2)
    
    with col1:
        activity_type = st.selectbox(
            "Activity Type",
            ["App Usage", "Communication Patterns", "Device Events"]
        )
    
    with col2:
        analysis_period = st.selectbox(
            "Analysis Period",
            ["Daily", "Weekly", "Monthly"]
        )
    
    try:
        # Create activity chart
        activity_fig = create_activity_chart(
            case_id=case_id,
            activity_type=activity_type,
            period=analysis_period
        )
        
        if activity_fig:
            st.plotly_chart(activity_fig, use_container_width=True)
        else:
            st.info("No activity data available for analysis.")
    
    except Exception as e:
        st.error(f"Error creating activity chart: {str(e)}")
    
    # Activity summary
    st.markdown("#### Activity Summary")
    
    try:
        # Show activity statistics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Peak Activity Hour", "N/A")  # Replace with actual data
        with col2:
            st.metric("Most Active Day", "N/A")  # Replace with actual data
        with col3:
            st.metric("Average Daily Events", "N/A")  # Replace with actual data
    
    except Exception as e:
        st.error(f"Error calculating activity summary: {str(e)}")
    
    # Behavioral patterns
    st.markdown("#### Behavioral Patterns")
    
    try:
        # Show behavioral analysis
        st.info("Behavioral pattern analysis will be displayed here.")
    
    except Exception as e:
        st.error(f"Error analyzing behavioral patterns: {str(e)}")

if __name__ == "__main__":
    main()
