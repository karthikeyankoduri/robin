import streamlit as st
import os
import tempfile
from datetime import datetime
from utils.db import get_db_session, Case
from utils.parsers import detect_file_type, parse_ufdr_file
from utils.security import check_authentication, log_audit_event
import magic

st.set_page_config(
    page_title="Upload - Robin",
    page_icon="📁",
    layout="wide"
)

def main():
    st.title("📁 Upload UFDR Files")
    st.markdown("Upload and parse Universal Forensic Data Report files (CSV, JSON, XML, SQLite)")
    
    if not check_authentication():
        return
    
    # Case selection/creation
    st.markdown("### Case Management")
    
    session = get_db_session()
    try:
        cases = session.query(Case).all()
        case_options = {f"{case.name} (ID: {case.id})": case.id for case in cases}
        case_options["Create New Case"] = "new"
        
        selected_case = st.selectbox("Select Case", options=list(case_options.keys()))
        
        if case_options[selected_case] == "new":
            st.markdown("#### Create New Case")
            col1, col2 = st.columns(2)
            with col1:
                case_name = st.text_input("Case Name*", placeholder="e.g., Mobile Device Analysis #123")
            with col2:
                case_description = st.text_area("Description", placeholder="Brief description of the case")
            
            investigator_name = st.text_input("Lead Investigator*", placeholder="Officer name")
            
            if st.button("Create Case"):
                if case_name and investigator_name:
                    new_case = Case(
                        name=case_name,
                        description=case_description,
                        investigator=investigator_name,
                        created_at=datetime.utcnow()
                    )
                    session.add(new_case)
                    session.commit()
                    
                    log_audit_event(
                        session,
                        investigator_name,
                        "CASE_CREATED",
                        f"Created new case: {case_name}"
                    )
                    
                    st.success(f"Case '{case_name}' created successfully!")
                    st.rerun()
                else:
                    st.error("Please fill in all required fields.")
        else:
            case_id = case_options[selected_case]
            st.success(f"Selected case: {selected_case}")
        
    except Exception as e:
        st.error(f"Error loading cases: {str(e)}")
        session.rollback()
    finally:
        session.close()
    
    # File upload section
    st.markdown("### File Upload")
    
    uploaded_files = st.file_uploader(
        "Choose UFDR files",
        accept_multiple_files=True,
        type=['csv', 'json', 'xml', 'db', 'sqlite', 'sqlite3'],
        help="Supported formats: CSV, JSON, XML, SQLite"
    )
    
    if uploaded_files and case_options.get(selected_case, "new") != "new":
        case_id = case_options[selected_case]
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        for i, uploaded_file in enumerate(uploaded_files):
            try:
                status_text.text(f"Processing {uploaded_file.name}...")
                
                # Save uploaded file temporarily
                with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}") as tmp_file:
                    tmp_file.write(uploaded_file.getvalue())
                    tmp_file_path = tmp_file.name
                
                # Detect file type
                file_type = detect_file_type(tmp_file_path)
                st.info(f"Detected file type: {file_type}")
                
                # Parse file
                session = get_db_session()
                try:
                    parse_result = parse_ufdr_file(tmp_file_path, file_type, case_id, session)
                    
                    if parse_result['success']:
                        st.success(f"✅ {uploaded_file.name}: {parse_result['message']}")
                        
                        # Log the upload
                        log_audit_event(
                            session,
                            st.session_state.get('username', 'unknown'),
                            "FILE_UPLOADED",
                            f"Uploaded and parsed {uploaded_file.name} ({file_type}). Records: {parse_result.get('records_count', 0)}"
                        )
                        
                        session.commit()
                    else:
                        st.error(f"❌ {uploaded_file.name}: {parse_result['message']}")
                        session.rollback()
                
                except Exception as e:
                    st.error(f"❌ Error parsing {uploaded_file.name}: {str(e)}")
                    session.rollback()
                finally:
                    session.close()
                
                # Cleanup temporary file
                os.unlink(tmp_file_path)
                
            except Exception as e:
                st.error(f"❌ Error processing {uploaded_file.name}: {str(e)}")
            
            # Update progress
            progress_bar.progress((i + 1) / len(uploaded_files))
        
        status_text.text("Processing complete!")
        
        if st.button("🔍 Go to Search"):
            st.switch_page("pages/2_Search.py")
    
    elif uploaded_files:
        st.warning("Please select or create a case before uploading files.")
    
    # Upload guidelines
    st.markdown("### Upload Guidelines")
    st.markdown("""
    **Supported File Formats:**
    - **CSV**: Chat messages, call logs, contacts with standard headers
    - **JSON**: Structured data exports from mobile forensic tools
    - **XML**: XML-formatted UFDR reports
    - **SQLite**: Database files from mobile applications
    
    **Data Types Processed:**
    - Chat messages (WhatsApp, SMS, Telegram, etc.)
    - Call logs and metadata
    - Contacts and address books
    - Media files with EXIF metadata
    - Location data (GPS coordinates)
    - App usage logs and timestamps
    
    **Security Note:** All uploaded files are processed securely and logged for audit purposes.
    """)

if __name__ == "__main__":
    main()
