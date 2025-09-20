import streamlit as st
import pandas as pd
import json
from datetime import datetime
from utils.db import get_db_session, Case, ChatMessage, Call, Contact
from utils.security import check_authentication, log_audit_event
from utils.ai import (
    summarize_conversations, extract_entities_from_text, 
    analyze_sentiment_batch, detect_anomalies, generate_investigation_report
)

st.set_page_config(
    page_title="AI Analysis - Robin",
    page_icon="🤖",
    layout="wide"
)

def main():
    st.title("🤖 AI-Powered Analysis")
    st.markdown("Advanced AI analysis for forensic data including NER, sentiment analysis, and pattern detection")
    
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
        selected_case_display = st.selectbox("Select Case for AI Analysis", options=list(case_options.keys()))
        case_id = case_options[selected_case_display]
        
    except Exception as e:
        st.error(f"Error loading cases: {str(e)}")
        return
    finally:
        session.close()
    
    # AI Analysis tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "💬 Text Analysis", "👤 Entity Extraction", "😊 Sentiment Analysis", 
        "🔍 Anomaly Detection", "📄 Reports"
    ])
    
    with tab1:
        display_text_analysis(case_id)
    
    with tab2:
        display_entity_extraction(case_id)
    
    with tab3:
        display_sentiment_analysis(case_id)
    
    with tab4:
        display_anomaly_detection(case_id)
    
    with tab5:
        display_report_generation(case_id)

def display_text_analysis(case_id):
    """Display text summarization and analysis"""
    st.markdown("### Text Summarization & Analysis")
    
    # Analysis options
    col1, col2 = st.columns(2)
    
    with col1:
        analysis_type = st.selectbox(
            "Analysis Type",
            ["Conversation Summaries", "Call Log Analysis", "Contact Notes Analysis"]
        )
    
    with col2:
        summary_length = st.selectbox(
            "Summary Length",
            ["Brief", "Detailed", "Comprehensive"]
        )
    
    # Data source selection
    if analysis_type == "Conversation Summaries":
        chat_filter = st.selectbox(
            "Chat Filter",
            ["All Conversations", "Group Chats Only", "Individual Chats Only", "Most Active"]
        )
    
    if st.button("🔄 Generate Analysis", type="primary"):
        with st.spinner("Analyzing text data..."):
            try:
                session = get_db_session()
                
                if analysis_type == "Conversation Summaries":
                    results = generate_conversation_summaries(session, case_id, chat_filter, summary_length)
                elif analysis_type == "Call Log Analysis":
                    results = generate_call_analysis(session, case_id, summary_length)
                else:
                    results = generate_contact_analysis(session, case_id, summary_length)
                
                display_text_analysis_results(results, analysis_type)
                
                # Log the analysis
                log_audit_event(
                    session,
                    st.session_state.get('username', 'unknown'),
                    "AI_ANALYSIS",
                    f"Generated {analysis_type} for case {case_id}"
                )
                
                session.close()
                
            except Exception as e:
                st.error(f"Analysis error: {str(e)}")

def display_entity_extraction(case_id):
    """Display Named Entity Recognition results"""
    st.markdown("### Named Entity Recognition (NER)")
    
    # Entity extraction options
    col1, col2 = st.columns(2)
    
    with col1:
        entity_types = st.multiselect(
            "Entity Types to Extract",
            ["PERSON", "ORG", "GPE", "PHONE", "EMAIL", "DATE", "MONEY", "LOC"],
            default=["PERSON", "ORG", "GPE", "PHONE"]
        )
    
    with col2:
        confidence_threshold = st.slider(
            "Confidence Threshold",
            min_value=0.1,
            max_value=1.0,
            value=0.7,
            step=0.1
        )
    
    # Source selection
    source_type = st.selectbox(
        "Data Source",
        ["Chat Messages", "Contact Notes", "Call Logs", "All Sources"]
    )
    
    if st.button("🔍 Extract Entities", type="primary"):
        with st.spinner("Extracting entities..."):
            try:
                session = get_db_session()
                entities = extract_entities_from_case(
                    session, case_id, source_type, entity_types, confidence_threshold
                )
                
                display_entity_results(entities)
                
                # Log the extraction
                log_audit_event(
                    session,
                    st.session_state.get('username', 'unknown'),
                    "ENTITY_EXTRACTION",
                    f"Extracted entities from {source_type} for case {case_id}"
                )
                
                session.close()
                
            except Exception as e:
                st.error(f"Entity extraction error: {str(e)}")

def display_sentiment_analysis(case_id):
    """Display sentiment analysis results"""
    st.markdown("### Sentiment Analysis")
    
    # Sentiment analysis options
    col1, col2 = st.columns(2)
    
    with col1:
        analysis_scope = st.selectbox(
            "Analysis Scope",
            ["Individual Messages", "Conversation Threads", "Contact Relationships", "Overall Mood"]
        )
    
    with col2:
        time_period = st.selectbox(
            "Time Period",
            ["All Time", "Last 7 Days", "Last 30 Days", "Last 3 Months"]
        )
    
    # Sentiment visualization type
    viz_type = st.selectbox(
        "Visualization Type",
        ["Timeline Chart", "Contact Comparison", "Emotion Distribution", "Trend Analysis"]
    )
    
    if st.button("📊 Analyze Sentiment", type="primary"):
        with st.spinner("Analyzing sentiment..."):
            try:
                session = get_db_session()
                sentiment_results = perform_sentiment_analysis(
                    session, case_id, analysis_scope, time_period
                )
                
                display_sentiment_results(sentiment_results, viz_type)
                
                # Log the analysis
                log_audit_event(
                    session,
                    st.session_state.get('username', 'unknown'),
                    "SENTIMENT_ANALYSIS",
                    f"Performed sentiment analysis for case {case_id}"
                )
                
                session.close()
                
            except Exception as e:
                st.error(f"Sentiment analysis error: {str(e)}")

def display_anomaly_detection(case_id):
    """Display anomaly detection results"""
    st.markdown("### Anomaly Detection")
    
    # Anomaly detection options
    col1, col2 = st.columns(2)
    
    with col1:
        detection_type = st.selectbox(
            "Detection Type",
            ["Communication Patterns", "Location Anomalies", "Temporal Anomalies", "Content Anomalies"]
        )
    
    with col2:
        sensitivity = st.selectbox(
            "Sensitivity Level",
            ["Low", "Medium", "High"]
        )
    
    # Advanced options
    with st.expander("Advanced Options"):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            outlier_threshold = st.slider("Outlier Threshold", 0.1, 2.0, 1.5, 0.1)
        with col2:
            min_samples = st.number_input("Minimum Samples", 5, 100, 20)
        with col3:
            algorithm = st.selectbox("Algorithm", ["Isolation Forest", "Local Outlier Factor", "One-Class SVM"])
    
    if st.button("🕵️ Detect Anomalies", type="primary"):
        with st.spinner("Detecting anomalies..."):
            try:
                session = get_db_session()
                anomalies = detect_case_anomalies(
                    session, case_id, detection_type, sensitivity, 
                    outlier_threshold, min_samples, algorithm
                )
                
                display_anomaly_results(anomalies, detection_type)
                
                # Log the detection
                log_audit_event(
                    session,
                    st.session_state.get('username', 'unknown'),
                    "ANOMALY_DETECTION",
                    f"Detected {detection_type} anomalies for case {case_id}"
                )
                
                session.close()
                
            except Exception as e:
                st.error(f"Anomaly detection error: {str(e)}")

def display_report_generation(case_id):
    """Display AI-generated investigation reports"""
    st.markdown("### AI Investigation Reports")
    
    # Report options
    col1, col2 = st.columns(2)
    
    with col1:
        report_type = st.selectbox(
            "Report Type",
            ["Executive Summary", "Detailed Analysis", "Evidence Summary", "Timeline Report"]
        )
    
    with col2:
        include_sections = st.multiselect(
            "Include Sections",
            ["Key Findings", "Entity Analysis", "Communication Patterns", "Location Data", "Anomalies", "Recommendations"],
            default=["Key Findings", "Communication Patterns", "Recommendations"]
        )
    
    # Report format
    output_format = st.selectbox(
        "Output Format",
        ["Structured Text", "JSON", "Markdown"]
    )
    
    if st.button("📄 Generate Report", type="primary"):
        with st.spinner("Generating AI report..."):
            try:
                session = get_db_session()
                report = generate_ai_investigation_report(
                    session, case_id, report_type, include_sections, output_format
                )
                
                display_generated_report(report, output_format)
                
                # Log the report generation
                log_audit_event(
                    session,
                    st.session_state.get('username', 'unknown'),
                    "REPORT_GENERATED",
                    f"Generated {report_type} report for case {case_id}"
                )
                
                session.close()
                
            except Exception as e:
                st.error(f"Report generation error: {str(e)}")

# Helper functions for each analysis type

def generate_conversation_summaries(session, case_id, chat_filter, summary_length):
    """Generate AI summaries of conversations"""
    # Query chat messages based on filter
    query = session.query(ChatMessage).filter(ChatMessage.case_id == case_id)
    
    if chat_filter == "Group Chats Only":
        # Add logic to filter group chats
        pass
    elif chat_filter == "Individual Chats Only":
        # Add logic to filter individual chats  
        pass
    
    messages = query.all()
    
    # Group messages by conversation/chat_id and generate summaries
    conversations = {}
    for msg in messages:
        chat_id = msg.chat_id or "unknown"
        if chat_id not in conversations:
            conversations[chat_id] = []
        conversations[chat_id].append(msg)
    
    summaries = []
    for chat_id, msgs in conversations.items():
        if len(msgs) >= 5:  # Only summarize substantial conversations
            conversation_text = "\n".join([f"{msg.sender}: {msg.content}" for msg in msgs[:50]])  # Limit for API
            summary = summarize_conversations(conversation_text, summary_length)
            summaries.append({
                'chat_id': chat_id,
                'message_count': len(msgs),
                'participants': list(set([msg.sender for msg in msgs if msg.sender])),
                'summary': summary,
                'date_range': f"{msgs[0].timestamp} to {msgs[-1].timestamp}"
            })
    
    return summaries

def extract_entities_from_case(session, case_id, source_type, entity_types, confidence_threshold):
    """Extract entities from case data"""
    entities = []
    
    if source_type in ["Chat Messages", "All Sources"]:
        messages = session.query(ChatMessage).filter(ChatMessage.case_id == case_id).all()
        for msg in messages:
            if msg.content:
                msg_entities = extract_entities_from_text(msg.content, entity_types, confidence_threshold)
                for entity in msg_entities:
                    entity['source'] = 'chat_message'
                    entity['source_id'] = msg.id
                    entity['timestamp'] = msg.timestamp
                entities.extend(msg_entities)
    
    # Add similar logic for other source types
    
    return entities

def perform_sentiment_analysis(session, case_id, analysis_scope, time_period):
    """Perform sentiment analysis on case data"""
    # Implementation for sentiment analysis
    results = {
        'overall_sentiment': 'neutral',
        'sentiment_timeline': [],
        'contact_sentiments': {},
        'emotion_distribution': {}
    }
    
    # Query relevant data and perform analysis
    messages = session.query(ChatMessage).filter(ChatMessage.case_id == case_id).all()
    
    if messages:
        texts = [msg.content for msg in messages if msg.content]
        if texts:
            sentiment_results = analyze_sentiment_batch(texts)
            # Process and structure results
            results['overall_sentiment'] = sentiment_results.get('overall', 'neutral')
    
    return results

def detect_case_anomalies(session, case_id, detection_type, sensitivity, outlier_threshold, min_samples, algorithm):
    """Detect anomalies in case data"""
    anomalies = []
    
    try:
        # Get case data for anomaly detection
        if detection_type == "Communication Patterns":
            # Detect unusual communication patterns
            messages = session.query(ChatMessage).filter(ChatMessage.case_id == case_id).all()
            anomalies = detect_anomalies(messages, detection_type, sensitivity)
        
        # Add logic for other detection types
        
    except Exception as e:
        st.error(f"Anomaly detection failed: {str(e)}")
    
    return anomalies

def generate_ai_investigation_report(session, case_id, report_type, include_sections, output_format):
    """Generate comprehensive AI investigation report"""
    # Gather data for report
    case = session.query(Case).filter(Case.id == case_id).first()
    
    report_data = {
        'case_info': {
            'name': case.name,
            'investigator': case.investigator,
            'created_at': case.created_at,
            'description': case.description
        },
        'sections': {}
    }
    
    # Generate each requested section
    for section in include_sections:
        if section == "Key Findings":
            report_data['sections'][section] = generate_key_findings(session, case_id)
        elif section == "Communication Patterns":
            report_data['sections'][section] = analyze_communication_patterns(session, case_id)
        # Add other sections
    
    # Generate final report using AI
    report = generate_investigation_report(report_data, report_type, output_format)
    
    return report

# Display functions for results

def display_text_analysis_results(results, analysis_type):
    """Display text analysis results"""
    if not results:
        st.info("No analysis results available.")
        return
    
    st.markdown(f"#### {analysis_type} Results")
    
    for i, result in enumerate(results):
        with st.expander(f"Analysis {i+1}: {result.get('title', 'Summary')}"):
            if 'summary' in result:
                st.markdown("**Summary:**")
                st.write(result['summary'])
            
            if 'participants' in result:
                st.markdown("**Participants:**")
                st.write(", ".join(result['participants']))
            
            if 'message_count' in result:
                st.markdown(f"**Message Count:** {result['message_count']}")
            
            if 'date_range' in result:
                st.markdown(f"**Date Range:** {result['date_range']}")

def display_entity_results(entities):
    """Display entity extraction results"""
    if not entities:
        st.info("No entities found.")
        return
    
    # Group entities by type
    entity_groups = {}
    for entity in entities:
        entity_type = entity.get('label', 'UNKNOWN')
        if entity_type not in entity_groups:
            entity_groups[entity_type] = []
        entity_groups[entity_type].append(entity)
    
    # Display entities by type
    for entity_type, type_entities in entity_groups.items():
        st.markdown(f"#### {entity_type} Entities ({len(type_entities)})")
        
        # Create DataFrame for display
        df_data = []
        for entity in type_entities:
            df_data.append({
                'Text': entity.get('text', ''),
                'Confidence': f"{entity.get('confidence', 0):.2f}",
                'Source': entity.get('source', ''),
                'Timestamp': entity.get('timestamp', '')
            })
        
        if df_data:
            df = pd.DataFrame(df_data)
            st.dataframe(df, use_container_width=True)

def display_sentiment_results(sentiment_results, viz_type):
    """Display sentiment analysis results"""
    if not sentiment_results:
        st.info("No sentiment data available.")
        return
    
    st.markdown("#### Sentiment Analysis Results")
    
    # Overall sentiment
    overall = sentiment_results.get('overall_sentiment', 'neutral')
    sentiment_color = {'positive': 'green', 'negative': 'red', 'neutral': 'gray'}.get(overall, 'gray')
    st.markdown(f"**Overall Sentiment:** :{sentiment_color}[{overall.title()}]")
    
    # Display based on visualization type
    if viz_type == "Emotion Distribution" and sentiment_results.get('emotion_distribution'):
        emotions = sentiment_results['emotion_distribution']
        fig = px.pie(
            values=list(emotions.values()),
            names=list(emotions.keys()),
            title="Emotion Distribution"
        )
        st.plotly_chart(fig, use_container_width=True)

def display_anomaly_results(anomalies, detection_type):
    """Display anomaly detection results"""
    if not anomalies:
        st.success("No anomalies detected.")
        return
    
    st.markdown(f"#### {detection_type} Anomalies ({len(anomalies)} found)")
    
    for i, anomaly in enumerate(anomalies):
        with st.expander(f"Anomaly {i+1}: {anomaly.get('type', 'Unknown')}"):
            st.markdown(f"**Severity:** {anomaly.get('severity', 'Unknown')}")
            st.markdown(f"**Description:** {anomaly.get('description', 'No description')}")
            
            if anomaly.get('timestamp'):
                st.markdown(f"**Timestamp:** {anomaly['timestamp']}")
            
            if anomaly.get('confidence'):
                st.markdown(f"**Confidence:** {anomaly['confidence']:.2f}")

def display_generated_report(report, output_format):
    """Display generated AI report"""
    if not report:
        st.error("Failed to generate report.")
        return
    
    st.markdown("#### Generated Investigation Report")
    
    if output_format == "Structured Text":
        st.markdown(report)
    elif output_format == "JSON":
        st.json(report)
    elif output_format == "Markdown":
        st.markdown(report)
    
    # Download button
    if isinstance(report, str):
        st.download_button(
            label="📄 Download Report",
            data=report,
            file_name=f"investigation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{output_format.lower()}",
            mime="text/plain"
        )

# Additional helper functions

def generate_key_findings(session, case_id):
    """Generate key findings for a case"""
    # Implementation for key findings
    return "Key findings will be generated here based on case analysis."

def analyze_communication_patterns(session, case_id):
    """Analyze communication patterns for a case"""
    # Implementation for communication pattern analysis
    return "Communication pattern analysis results will be displayed here."

if __name__ == "__main__":
    main()
