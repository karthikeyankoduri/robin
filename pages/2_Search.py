import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from utils.db import get_db_session, Case, ChatMessage, Call, Contact, Media, Location
from utils.security import check_authentication
from utils.search import perform_full_text_search, SearchFilters

st.set_page_config(
    page_title="Search - Robin",
    page_icon="🔍",
    layout="wide"
)

def main():
    st.title("🔍 Advanced Search")
    st.markdown("Search across chats, calls, contacts, and media metadata")
    
    if not check_authentication():
        return
    
    # Search interface
    col1, col2 = st.columns([2, 1])
    
    with col1:
        search_query = st.text_input(
            "Search Query",
            placeholder="Enter keywords, phone numbers, names, or locations...",
            help="Use quotes for exact phrases, OR/AND for boolean search"
        )
    
    with col2:
        search_type = st.selectbox(
            "Search Type",
            ["All Data", "Chat Messages", "Call Logs", "Contacts", "Media", "Locations"]
        )
    
    # Advanced filters
    with st.expander("Advanced Filters"):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            # Case filter
            session = get_db_session()
            try:
                cases = session.query(Case).all()
                case_options = ["All Cases"] + [f"{case.name} (ID: {case.id})" for case in cases]
                selected_case = st.selectbox("Case", case_options)
                case_id = None if selected_case == "All Cases" else cases[case_options.index(selected_case) - 1].id
            except Exception as e:
                st.error(f"Error loading cases: {str(e)}")
                case_id = None
            finally:
                session.close()
        
        with col2:
            # Date range filter
            date_filter = st.selectbox(
                "Date Range",
                ["All Time", "Last 24 Hours", "Last Week", "Last Month", "Custom Range"]
            )
            
            start_date = None
            end_date = None
            
            if date_filter == "Last 24 Hours":
                start_date = datetime.now() - timedelta(days=1)
            elif date_filter == "Last Week":
                start_date = datetime.now() - timedelta(weeks=1)
            elif date_filter == "Last Month":
                start_date = datetime.now() - timedelta(days=30)
            elif date_filter == "Custom Range":
                col_start, col_end = st.columns(2)
                with col_start:
                    start_date = st.date_input("Start Date")
                with col_end:
                    end_date = st.date_input("End Date")
        
        with col3:
            # Additional filters
            include_deleted = st.checkbox("Include Deleted Items")
            media_only = st.checkbox("Media Files Only")
    
    # Perform search
    if st.button("🔍 Search", type="primary") or search_query:
        if search_query:
            with st.spinner("Searching..."):
                search_filters = SearchFilters(
                    case_id=case_id,
                    search_type=search_type,
                    start_date=start_date,
                    end_date=end_date,
                    include_deleted=include_deleted,
                    media_only=media_only
                )
                
                try:
                    results = perform_full_text_search(search_query, search_filters)
                    display_search_results(results, search_query)
                except Exception as e:
                    st.error(f"Search error: {str(e)}")
        else:
            st.warning("Please enter a search query.")
    
    # Recent searches
    if 'recent_searches' not in st.session_state:
        st.session_state.recent_searches = []
    
    if st.session_state.recent_searches:
        st.markdown("### Recent Searches")
        for i, recent_search in enumerate(st.session_state.recent_searches[-5:]):
            col1, col2 = st.columns([4, 1])
            with col1:
                st.text(f"'{recent_search['query']}' in {recent_search['type']}")
            with col2:
                if st.button("Repeat", key=f"repeat_{i}"):
                    search_query = recent_search['query']
                    search_type = recent_search['type']
                    st.rerun()

def display_search_results(results, query):
    """Display search results in organized tabs"""
    
    if not results:
        st.info("No results found for your search query.")
        return
    
    # Add to recent searches
    if 'recent_searches' not in st.session_state:
        st.session_state.recent_searches = []
    
    st.session_state.recent_searches.append({
        'query': query,
        'type': 'All Data',
        'timestamp': datetime.now()
    })
    
    st.markdown(f"### Search Results ({len(results)} found)")
    
    # Group results by type
    result_types = {}
    for result in results:
        result_type = result.get('type', 'Unknown')
        if result_type not in result_types:
            result_types[result_type] = []
        result_types[result_type].append(result)
    
    # Display results in tabs
    if len(result_types) > 1:
        tabs = st.tabs(list(result_types.keys()))
        for i, (result_type, type_results) in enumerate(result_types.items()):
            with tabs[i]:
                display_results_by_type(type_results, result_type)
    else:
        result_type = list(result_types.keys())[0]
        display_results_by_type(result_types[result_type], result_type)
    
    # Export options
    st.markdown("### Export Results")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📊 Export to CSV"):
            export_results_csv(results)
    
    with col2:
        if st.button("📋 Copy to Clipboard"):
            export_results_text(results)
    
    with col3:
        if st.button("📈 Visualize Timeline"):
            st.switch_page("pages/3_Visualization.py")

def display_results_by_type(results, result_type):
    """Display results for a specific data type"""
    
    if result_type == "ChatMessage":
        display_chat_results(results)
    elif result_type == "Call":
        display_call_results(results)
    elif result_type == "Contact":
        display_contact_results(results)
    elif result_type == "Media":
        display_media_results(results)
    elif result_type == "Location":
        display_location_results(results)
    else:
        # Generic display
        for result in results:
            with st.expander(f"{result.get('title', 'Result')} - {result.get('timestamp', 'N/A')}"):
                st.json(result)

def display_chat_results(results):
    """Display chat message search results"""
    for result in results:
        with st.expander(f"💬 {result.get('sender', 'Unknown')} - {result.get('timestamp', 'N/A')}"):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.markdown(f"**Message:** {result.get('content', 'N/A')}")
                if result.get('app_name'):
                    st.markdown(f"**App:** {result['app_name']}")
                if result.get('chat_id'):
                    st.markdown(f"**Chat ID:** {result['chat_id']}")
            
            with col2:
                st.markdown(f"**Direction:** {result.get('direction', 'N/A')}")
                if result.get('coordinates'):
                    st.markdown(f"**Location:** {result['coordinates']}")

def display_call_results(results):
    """Display call log search results"""
    for result in results:
        with st.expander(f"📞 {result.get('phone_number', 'Unknown')} - {result.get('timestamp', 'N/A')}"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown(f"**Type:** {result.get('call_type', 'N/A')}")
                st.markdown(f"**Duration:** {result.get('duration', 'N/A')} seconds")
            
            with col2:
                st.markdown(f"**Direction:** {result.get('direction', 'N/A')}")
                if result.get('coordinates'):
                    st.markdown(f"**Location:** {result['coordinates']}")

def display_contact_results(results):
    """Display contact search results"""
    for result in results:
        with st.expander(f"👤 {result.get('name', 'Unknown')}"):
            col1, col2 = st.columns(2)
            
            with col1:
                if result.get('phone_numbers'):
                    st.markdown(f"**Phone:** {result['phone_numbers']}")
                if result.get('emails'):
                    st.markdown(f"**Email:** {result['emails']}")
            
            with col2:
                if result.get('organization'):
                    st.markdown(f"**Organization:** {result['organization']}")
                if result.get('notes'):
                    st.markdown(f"**Notes:** {result['notes']}")

def display_media_results(results):
    """Display media search results"""
    for result in results:
        with st.expander(f"🖼️ {result.get('file_name', 'Unknown')} - {result.get('timestamp', 'N/A')}"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown(f"**File Type:** {result.get('file_type', 'N/A')}")
                st.markdown(f"**Size:** {result.get('file_size', 'N/A')} bytes")
            
            with col2:
                if result.get('coordinates'):
                    st.markdown(f"**Location:** {result['coordinates']}")
                if result.get('camera_make'):
                    st.markdown(f"**Camera:** {result['camera_make']} {result.get('camera_model', '')}")

def display_location_results(results):
    """Display location search results"""
    for result in results:
        with st.expander(f"📍 {result.get('coordinates', 'Unknown')} - {result.get('timestamp', 'N/A')}"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown(f"**Accuracy:** {result.get('accuracy', 'N/A')} meters")
                if result.get('altitude'):
                    st.markdown(f"**Altitude:** {result['altitude']} meters")
            
            with col2:
                if result.get('source'):
                    st.markdown(f"**Source:** {result['source']}")
                if result.get('activity'):
                    st.markdown(f"**Activity:** {result['activity']}")

def export_results_csv(results):
    """Export search results to CSV"""
    try:
        df = pd.DataFrame(results)
        csv = df.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"search_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    except Exception as e:
        st.error(f"Export error: {str(e)}")

def export_results_text(results):
    """Export search results to clipboard-friendly text"""
    try:
        text_output = []
        for i, result in enumerate(results, 1):
            text_output.append(f"Result {i}:")
            for key, value in result.items():
                text_output.append(f"  {key}: {value}")
            text_output.append("")
        
        st.text_area("Copy this text:", "\n".join(text_output), height=200)
    except Exception as e:
        st.error(f"Export error: {str(e)}")

if __name__ == "__main__":
    main()
