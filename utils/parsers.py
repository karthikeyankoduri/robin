import csv
import json
import xml.etree.ElementTree as ET
import sqlite3
import pandas as pd
import magic
import os
from datetime import datetime
import logging
from typing import Dict, List, Any, Optional
from utils.db import get_db_session, ChatMessage, Call, Contact, Media, Location

logger = logging.getLogger(__name__)

def detect_file_type(file_path: str) -> str:
    """Detect file type using python-magic and file extension"""
    try:
        # First try using python-magic for MIME type detection
        mime_type = magic.from_file(file_path, mime=True)
        
        # Get file extension
        _, ext = os.path.splitext(file_path.lower())
        
        # Map MIME types and extensions to our supported formats
        if mime_type == 'text/csv' or ext == '.csv':
            return 'CSV'
        elif mime_type in ['application/json', 'text/json'] or ext == '.json':
            return 'JSON'
        elif mime_type in ['application/xml', 'text/xml'] or ext == '.xml':
            return 'XML'
        elif mime_type == 'application/x-sqlite3' or ext in ['.db', '.sqlite', '.sqlite3']:
            return 'SQLITE'
        else:
            # Fallback to extension-based detection
            if ext == '.csv':
                return 'CSV'
            elif ext == '.json':
                return 'JSON'
            elif ext == '.xml':
                return 'XML'
            elif ext in ['.db', '.sqlite', '.sqlite3']:
                return 'SQLITE'
            else:
                return 'UNKNOWN'
    
    except Exception as e:
        logger.error(f"Error detecting file type for {file_path}: {e}")
        return 'UNKNOWN'

def parse_ufdr_file(file_path: str, file_type: str, case_id: int, session) -> Dict[str, Any]:
    """
    Parse UFDR file based on type and insert data into database
    Returns a result dictionary with success status and details
    """
    try:
        if file_type == 'CSV':
            return parse_csv_file(file_path, case_id, session)
        elif file_type == 'JSON':
            return parse_json_file(file_path, case_id, session)
        elif file_type == 'XML':
            return parse_xml_file(file_path, case_id, session)
        elif file_type == 'SQLITE':
            return parse_sqlite_file(file_path, case_id, session)
        else:
            return {
                'success': False,
                'message': f'Unsupported file type: {file_type}',
                'records_count': 0
            }
    
    except Exception as e:
        logger.error(f"Error parsing {file_type} file {file_path}: {e}")
        return {
            'success': False,
            'message': f'Parse error: {str(e)}',
            'records_count': 0
        }

def parse_csv_file(file_path: str, case_id: int, session) -> Dict[str, Any]:
    """Parse CSV UFDR file and extract forensic data"""
    records_count = 0
    
    try:
        # Read CSV file
        df = pd.read_csv(file_path, encoding='utf-8', low_memory=False)
        
        # Detect CSV type based on columns
        columns = [col.lower().strip() for col in df.columns]
        
        if detect_chat_message_csv(columns):
            records_count = parse_chat_messages_csv(df, case_id, session)
        elif detect_call_log_csv(columns):
            records_count = parse_call_logs_csv(df, case_id, session)
        elif detect_contacts_csv(columns):
            records_count = parse_contacts_csv(df, case_id, session)
        elif detect_media_csv(columns):
            records_count = parse_media_csv(df, case_id, session)
        elif detect_location_csv(columns):
            records_count = parse_location_csv(df, case_id, session)
        else:
            # Try to parse as generic data
            records_count = parse_generic_csv(df, case_id, session)
        
        return {
            'success': True,
            'message': f'Successfully parsed CSV file with {records_count} records',
            'records_count': records_count
        }
    
    except Exception as e:
        logger.error(f"Error parsing CSV file: {e}")
        raise

def parse_json_file(file_path: str, case_id: int, session) -> Dict[str, Any]:
    """Parse JSON UFDR file and extract forensic data"""
    records_count = 0
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle different JSON structures
        if isinstance(data, list):
            # Array of objects
            for item in data:
                if detect_chat_message_json(item):
                    records_count += parse_chat_message_json(item, case_id, session)
                elif detect_call_json(item):
                    records_count += parse_call_json(item, case_id, session)
                elif detect_contact_json(item):
                    records_count += parse_contact_json(item, case_id, session)
                elif detect_media_json(item):
                    records_count += parse_media_json(item, case_id, session)
                elif detect_location_json(item):
                    records_count += parse_location_json(item, case_id, session)
        
        elif isinstance(data, dict):
            # Object with nested arrays
            if 'messages' in data or 'chats' in data:
                messages = data.get('messages', data.get('chats', []))
                for msg in messages:
                    records_count += parse_chat_message_json(msg, case_id, session)
            
            if 'calls' in data or 'call_logs' in data:
                calls = data.get('calls', data.get('call_logs', []))
                for call in calls:
                    records_count += parse_call_json(call, case_id, session)
            
            if 'contacts' in data:
                contacts = data.get('contacts', [])
                for contact in contacts:
                    records_count += parse_contact_json(contact, case_id, session)
            
            if 'media' in data or 'files' in data:
                media = data.get('media', data.get('files', []))
                for item in media:
                    records_count += parse_media_json(item, case_id, session)
            
            if 'locations' in data or 'gps_data' in data:
                locations = data.get('locations', data.get('gps_data', []))
                for loc in locations:
                    records_count += parse_location_json(loc, case_id, session)
        
        return {
            'success': True,
            'message': f'Successfully parsed JSON file with {records_count} records',
            'records_count': records_count
        }
    
    except Exception as e:
        logger.error(f"Error parsing JSON file: {e}")
        raise

def parse_xml_file(file_path: str, case_id: int, session) -> Dict[str, Any]:
    """Parse XML UFDR file and extract forensic data"""
    records_count = 0
    
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Parse different XML structures based on root element and children
        for child in root:
            if child.tag.lower() in ['message', 'chat', 'sms']:
                records_count += parse_chat_message_xml(child, case_id, session)
            elif child.tag.lower() in ['call', 'call_log']:
                records_count += parse_call_xml(child, case_id, session)
            elif child.tag.lower() in ['contact', 'address_book_entry']:
                records_count += parse_contact_xml(child, case_id, session)
            elif child.tag.lower() in ['media', 'file', 'image', 'video']:
                records_count += parse_media_xml(child, case_id, session)
            elif child.tag.lower() in ['location', 'gps', 'coordinate']:
                records_count += parse_location_xml(child, case_id, session)
        
        return {
            'success': True,
            'message': f'Successfully parsed XML file with {records_count} records',
            'records_count': records_count
        }
    
    except Exception as e:
        logger.error(f"Error parsing XML file: {e}")
        raise

def parse_sqlite_file(file_path: str, case_id: int, session) -> Dict[str, Any]:
    """Parse SQLite UFDR file and extract forensic data"""
    records_count = 0
    
    try:
        # Connect to SQLite database
        sqlite_conn = sqlite3.connect(file_path)
        sqlite_conn.row_factory = sqlite3.Row  # Enable column access by name
        
        cursor = sqlite_conn.cursor()
        
        # Get list of tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        for table_row in tables:
            table_name = table_row[0]
            
            # Skip system tables
            if table_name.startswith('sqlite_'):
                continue
            
            # Analyze table structure
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns_info = cursor.fetchall()
            column_names = [col[1].lower() for col in columns_info]
            
            # Determine table type and parse accordingly
            if detect_chat_table(table_name, column_names):
                records_count += parse_chat_table_sqlite(cursor, table_name, case_id, session)
            elif detect_call_table(table_name, column_names):
                records_count += parse_call_table_sqlite(cursor, table_name, case_id, session)
            elif detect_contact_table(table_name, column_names):
                records_count += parse_contact_table_sqlite(cursor, table_name, case_id, session)
            elif detect_media_table(table_name, column_names):
                records_count += parse_media_table_sqlite(cursor, table_name, case_id, session)
            elif detect_location_table(table_name, column_names):
                records_count += parse_location_table_sqlite(cursor, table_name, case_id, session)
        
        sqlite_conn.close()
        
        return {
            'success': True,
            'message': f'Successfully parsed SQLite file with {records_count} records',
            'records_count': records_count
        }
    
    except Exception as e:
        logger.error(f"Error parsing SQLite file: {e}")
        raise

# Detection functions for CSV columns
def detect_chat_message_csv(columns: List[str]) -> bool:
    """Detect if CSV contains chat message data"""
    chat_indicators = ['message', 'content', 'text', 'sender', 'recipient', 'chat_id', 'timestamp']
    return any(indicator in ' '.join(columns) for indicator in chat_indicators)

def detect_call_log_csv(columns: List[str]) -> bool:
    """Detect if CSV contains call log data"""
    call_indicators = ['phone_number', 'call_type', 'duration', 'direction', 'contact_name']
    return any(indicator in ' '.join(columns) for indicator in call_indicators)

def detect_contacts_csv(columns: List[str]) -> bool:
    """Detect if CSV contains contact data"""
    contact_indicators = ['name', 'phone', 'email', 'contact', 'address_book']
    return any(indicator in ' '.join(columns) for indicator in contact_indicators)

def detect_media_csv(columns: List[str]) -> bool:
    """Detect if CSV contains media metadata"""
    media_indicators = ['file_name', 'file_path', 'file_type', 'exif', 'camera', 'image', 'video']
    return any(indicator in ' '.join(columns) for indicator in media_indicators)

def detect_location_csv(columns: List[str]) -> bool:
    """Detect if CSV contains location data"""
    location_indicators = ['latitude', 'longitude', 'coordinates', 'gps', 'location']
    return any(indicator in ' '.join(columns) for indicator in location_indicators)

# CSV parsing functions
def parse_chat_messages_csv(df: pd.DataFrame, case_id: int, session) -> int:
    """Parse chat messages from CSV"""
    count = 0
    
    for _, row in df.iterrows():
        try:
            message = ChatMessage(
                case_id=case_id,
                chat_id=safe_get_value(row, ['chat_id', 'conversation_id', 'thread_id']),
                app_name=safe_get_value(row, ['app_name', 'application', 'source']),
                sender=safe_get_value(row, ['sender', 'from', 'author']),
                recipient=safe_get_value(row, ['recipient', 'to', 'receiver']),
                content=safe_get_value(row, ['content', 'message', 'text', 'body']),
                timestamp=parse_timestamp(safe_get_value(row, ['timestamp', 'date', 'time', 'datetime'])),
                direction=safe_get_value(row, ['direction', 'type']),
                message_type=safe_get_value(row, ['message_type', 'msg_type', 'type']),
                coordinates=safe_get_value(row, ['coordinates', 'location', 'gps'])
            )
            
            session.add(message)
            count += 1
            
        except Exception as e:
            logger.warning(f"Failed to parse chat message row: {e}")
            continue
    
    return count

def parse_call_logs_csv(df: pd.DataFrame, case_id: int, session) -> int:
    """Parse call logs from CSV"""
    count = 0
    
    for _, row in df.iterrows():
        try:
            call = Call(
                case_id=case_id,
                phone_number=safe_get_value(row, ['phone_number', 'number', 'phone']),
                contact_name=safe_get_value(row, ['contact_name', 'name', 'contact']),
                call_type=safe_get_value(row, ['call_type', 'type']),
                direction=safe_get_value(row, ['direction', 'call_direction']),
                timestamp=parse_timestamp(safe_get_value(row, ['timestamp', 'date', 'time', 'datetime'])),
                duration=safe_get_int(safe_get_value(row, ['duration', 'call_duration'])),
                coordinates=safe_get_value(row, ['coordinates', 'location', 'gps']),
                cell_tower=safe_get_value(row, ['cell_tower', 'tower_id', 'cell_id'])
            )
            
            session.add(call)
            count += 1
            
        except Exception as e:
            logger.warning(f"Failed to parse call log row: {e}")
            continue
    
    return count

def parse_contacts_csv(df: pd.DataFrame, case_id: int, session) -> int:
    """Parse contacts from CSV"""
    count = 0
    
    for _, row in df.iterrows():
        try:
            # Handle multiple phone numbers and emails
            phone_numbers = safe_get_value(row, ['phone_numbers', 'phones', 'phone'])
            emails = safe_get_value(row, ['emails', 'email', 'email_addresses'])
            
            if isinstance(phone_numbers, str) and phone_numbers:
                phone_numbers = json.dumps([phone_numbers])
            if isinstance(emails, str) and emails:
                emails = json.dumps([emails])
            
            contact = Contact(
                case_id=case_id,
                name=safe_get_value(row, ['name', 'display_name', 'contact_name']),
                phone_numbers=phone_numbers,
                emails=emails,
                organization=safe_get_value(row, ['organization', 'company', 'org']),
                notes=safe_get_value(row, ['notes', 'description', 'comment']),
                created_at=parse_timestamp(safe_get_value(row, ['created_at', 'created', 'date_created'])),
                updated_at=parse_timestamp(safe_get_value(row, ['updated_at', 'modified', 'date_modified']))
            )
            
            session.add(contact)
            count += 1
            
        except Exception as e:
            logger.warning(f"Failed to parse contact row: {e}")
            continue
    
    return count

def parse_media_csv(df: pd.DataFrame, case_id: int, session) -> int:
    """Parse media metadata from CSV"""
    count = 0
    
    for _, row in df.iterrows():
        try:
            media = Media(
                case_id=case_id,
                file_name=safe_get_value(row, ['file_name', 'filename', 'name']),
                file_path=safe_get_value(row, ['file_path', 'path', 'location']),
                file_type=safe_get_value(row, ['file_type', 'type', 'format']),
                file_size=safe_get_int(safe_get_value(row, ['file_size', 'size'])),
                hash_md5=safe_get_value(row, ['hash_md5', 'md5', 'md5_hash']),
                hash_sha256=safe_get_value(row, ['hash_sha256', 'sha256', 'sha256_hash']),
                timestamp=parse_timestamp(safe_get_value(row, ['timestamp', 'date_taken', 'created_date'])),
                coordinates=safe_get_value(row, ['coordinates', 'gps_coordinates', 'location']),
                camera_make=safe_get_value(row, ['camera_make', 'make']),
                camera_model=safe_get_value(row, ['camera_model', 'model']),
                exif_data=safe_get_value(row, ['exif_data', 'exif', 'metadata'])
            )
            
            session.add(media)
            count += 1
            
        except Exception as e:
            logger.warning(f"Failed to parse media row: {e}")
            continue
    
    return count

def parse_location_csv(df: pd.DataFrame, case_id: int, session) -> int:
    """Parse location data from CSV"""
    count = 0
    
    for _, row in df.iterrows():
        try:
            location = Location(
                case_id=case_id,
                timestamp=parse_timestamp(safe_get_value(row, ['timestamp', 'date', 'time'])),
                latitude=safe_get_float(safe_get_value(row, ['latitude', 'lat'])),
                longitude=safe_get_float(safe_get_value(row, ['longitude', 'lng', 'lon'])),
                altitude=safe_get_float(safe_get_value(row, ['altitude', 'alt'])),
                accuracy=safe_get_float(safe_get_value(row, ['accuracy', 'precision'])),
                source=safe_get_value(row, ['source', 'provider', 'method']),
                activity=safe_get_value(row, ['activity', 'motion', 'state'])
            )
            
            session.add(location)
            count += 1
            
        except Exception as e:
            logger.warning(f"Failed to parse location row: {e}")
            continue
    
    return count

def parse_generic_csv(df: pd.DataFrame, case_id: int, session) -> int:
    """Parse generic CSV data by attempting to match columns to known fields"""
    count = 0
    columns = [col.lower().strip() for col in df.columns]
    
    # Try to determine the most likely data type based on column analysis
    chat_score = sum(1 for col in columns if any(indicator in col for indicator in ['message', 'content', 'text', 'sender']))
    call_score = sum(1 for col in columns if any(indicator in col for indicator in ['phone', 'call', 'duration']))
    contact_score = sum(1 for col in columns if any(indicator in col for indicator in ['name', 'contact', 'email']))
    
    if chat_score >= call_score and chat_score >= contact_score:
        count = parse_chat_messages_csv(df, case_id, session)
    elif call_score >= contact_score:
        count = parse_call_logs_csv(df, case_id, session)
    else:
        count = parse_contacts_csv(df, case_id, session)
    
    return count

# JSON detection and parsing functions
def detect_chat_message_json(item: dict) -> bool:
    """Detect if JSON item is a chat message"""
    indicators = ['message', 'content', 'text', 'sender', 'recipient', 'chat_id']
    return any(key.lower() in indicators for key in item.keys())

def detect_call_json(item: dict) -> bool:
    """Detect if JSON item is a call log"""
    indicators = ['phone_number', 'call_type', 'duration', 'direction']
    return any(key.lower() in indicators for key in item.keys())

def detect_contact_json(item: dict) -> bool:
    """Detect if JSON item is a contact"""
    indicators = ['name', 'phone', 'email', 'contact']
    return any(key.lower() in indicators for key in item.keys())

def detect_media_json(item: dict) -> bool:
    """Detect if JSON item is media metadata"""
    indicators = ['file_name', 'file_path', 'file_type', 'exif', 'camera']
    return any(key.lower() in indicators for key in item.keys())

def detect_location_json(item: dict) -> bool:
    """Detect if JSON item is location data"""
    indicators = ['latitude', 'longitude', 'coordinates', 'gps', 'location']
    return any(key.lower() in indicators for key in item.keys())

def parse_chat_message_json(item: dict, case_id: int, session) -> int:
    """Parse single chat message from JSON"""
    try:
        message = ChatMessage(
            case_id=case_id,
            chat_id=safe_get_dict_value(item, ['chat_id', 'conversation_id', 'thread_id']),
            app_name=safe_get_dict_value(item, ['app_name', 'application', 'source']),
            sender=safe_get_dict_value(item, ['sender', 'from', 'author']),
            recipient=safe_get_dict_value(item, ['recipient', 'to', 'receiver']),
            content=safe_get_dict_value(item, ['content', 'message', 'text', 'body']),
            timestamp=parse_timestamp(safe_get_dict_value(item, ['timestamp', 'date', 'time'])),
            direction=safe_get_dict_value(item, ['direction', 'type']),
            message_type=safe_get_dict_value(item, ['message_type', 'msg_type', 'type']),
            coordinates=safe_get_dict_value(item, ['coordinates', 'location', 'gps'])
        )
        
        session.add(message)
        return 1
        
    except Exception as e:
        logger.warning(f"Failed to parse chat message JSON: {e}")
        return 0

def parse_call_json(item: dict, case_id: int, session) -> int:
    """Parse single call log from JSON"""
    try:
        call = Call(
            case_id=case_id,
            phone_number=safe_get_dict_value(item, ['phone_number', 'number', 'phone']),
            contact_name=safe_get_dict_value(item, ['contact_name', 'name', 'contact']),
            call_type=safe_get_dict_value(item, ['call_type', 'type']),
            direction=safe_get_dict_value(item, ['direction', 'call_direction']),
            timestamp=parse_timestamp(safe_get_dict_value(item, ['timestamp', 'date', 'time'])),
            duration=safe_get_int(safe_get_dict_value(item, ['duration', 'call_duration'])),
            coordinates=safe_get_dict_value(item, ['coordinates', 'location', 'gps']),
            cell_tower=safe_get_dict_value(item, ['cell_tower', 'tower_id', 'cell_id'])
        )
        
        session.add(call)
        return 1
        
    except Exception as e:
        logger.warning(f"Failed to parse call JSON: {e}")
        return 0

def parse_contact_json(item: dict, case_id: int, session) -> int:
    """Parse single contact from JSON"""
    try:
        # Handle multiple phone numbers and emails
        phone_numbers = safe_get_dict_value(item, ['phone_numbers', 'phones', 'phone'])
        emails = safe_get_dict_value(item, ['emails', 'email', 'email_addresses'])
        
        if isinstance(phone_numbers, list):
            phone_numbers = json.dumps(phone_numbers)
        elif isinstance(phone_numbers, str) and phone_numbers:
            phone_numbers = json.dumps([phone_numbers])
        
        if isinstance(emails, list):
            emails = json.dumps(emails)
        elif isinstance(emails, str) and emails:
            emails = json.dumps([emails])
        
        contact = Contact(
            case_id=case_id,
            name=safe_get_dict_value(item, ['name', 'display_name', 'contact_name']),
            phone_numbers=phone_numbers,
            emails=emails,
            organization=safe_get_dict_value(item, ['organization', 'company', 'org']),
            notes=safe_get_dict_value(item, ['notes', 'description', 'comment']),
            created_at=parse_timestamp(safe_get_dict_value(item, ['created_at', 'created'])),
            updated_at=parse_timestamp(safe_get_dict_value(item, ['updated_at', 'modified']))
        )
        
        session.add(contact)
        return 1
        
    except Exception as e:
        logger.warning(f"Failed to parse contact JSON: {e}")
        return 0

def parse_media_json(item: dict, case_id: int, session) -> int:
    """Parse single media item from JSON"""
    try:
        media = Media(
            case_id=case_id,
            file_name=safe_get_dict_value(item, ['file_name', 'filename', 'name']),
            file_path=safe_get_dict_value(item, ['file_path', 'path', 'location']),
            file_type=safe_get_dict_value(item, ['file_type', 'type', 'format']),
            file_size=safe_get_int(safe_get_dict_value(item, ['file_size', 'size'])),
            hash_md5=safe_get_dict_value(item, ['hash_md5', 'md5']),
            hash_sha256=safe_get_dict_value(item, ['hash_sha256', 'sha256']),
            timestamp=parse_timestamp(safe_get_dict_value(item, ['timestamp', 'date_taken', 'created'])),
            coordinates=safe_get_dict_value(item, ['coordinates', 'gps_coordinates', 'location']),
            camera_make=safe_get_dict_value(item, ['camera_make', 'make']),
            camera_model=safe_get_dict_value(item, ['camera_model', 'model']),
            exif_data=json.dumps(item.get('exif_data', item.get('exif', {}))) if item.get('exif_data') or item.get('exif') else None
        )
        
        session.add(media)
        return 1
        
    except Exception as e:
        logger.warning(f"Failed to parse media JSON: {e}")
        return 0

def parse_location_json(item: dict, case_id: int, session) -> int:
    """Parse single location from JSON"""
    try:
        location = Location(
            case_id=case_id,
            timestamp=parse_timestamp(safe_get_dict_value(item, ['timestamp', 'date', 'time'])),
            latitude=safe_get_float(safe_get_dict_value(item, ['latitude', 'lat'])),
            longitude=safe_get_float(safe_get_dict_value(item, ['longitude', 'lng', 'lon'])),
            altitude=safe_get_float(safe_get_dict_value(item, ['altitude', 'alt'])),
            accuracy=safe_get_float(safe_get_dict_value(item, ['accuracy', 'precision'])),
            source=safe_get_dict_value(item, ['source', 'provider', 'method']),
            activity=safe_get_dict_value(item, ['activity', 'motion', 'state'])
        )
        
        session.add(location)
        return 1
        
    except Exception as e:
        logger.warning(f"Failed to parse location JSON: {e}")
        return 0

# XML parsing functions
def parse_chat_message_xml(element, case_id: int, session) -> int:
    """Parse chat message from XML element"""
    try:
        message = ChatMessage(
            case_id=case_id,
            chat_id=safe_get_xml_value(element, ['chat_id', 'conversation_id', 'thread_id']),
            app_name=safe_get_xml_value(element, ['app_name', 'application', 'source']),
            sender=safe_get_xml_value(element, ['sender', 'from', 'author']),
            recipient=safe_get_xml_value(element, ['recipient', 'to', 'receiver']),
            content=safe_get_xml_value(element, ['content', 'message', 'text', 'body']),
            timestamp=parse_timestamp(safe_get_xml_value(element, ['timestamp', 'date', 'time'])),
            direction=safe_get_xml_value(element, ['direction', 'type']),
            message_type=safe_get_xml_value(element, ['message_type', 'msg_type', 'type']),
            coordinates=safe_get_xml_value(element, ['coordinates', 'location', 'gps'])
        )
        
        session.add(message)
        return 1
        
    except Exception as e:
        logger.warning(f"Failed to parse chat message XML: {e}")
        return 0

def parse_call_xml(element, case_id: int, session) -> int:
    """Parse call log from XML element"""
    try:
        call = Call(
            case_id=case_id,
            phone_number=safe_get_xml_value(element, ['phone_number', 'number', 'phone']),
            contact_name=safe_get_xml_value(element, ['contact_name', 'name', 'contact']),
            call_type=safe_get_xml_value(element, ['call_type', 'type']),
            direction=safe_get_xml_value(element, ['direction', 'call_direction']),
            timestamp=parse_timestamp(safe_get_xml_value(element, ['timestamp', 'date', 'time'])),
            duration=safe_get_int(safe_get_xml_value(element, ['duration', 'call_duration'])),
            coordinates=safe_get_xml_value(element, ['coordinates', 'location', 'gps']),
            cell_tower=safe_get_xml_value(element, ['cell_tower', 'tower_id', 'cell_id'])
        )
        
        session.add(call)
        return 1
        
    except Exception as e:
        logger.warning(f"Failed to parse call XML: {e}")
        return 0

def parse_contact_xml(element, case_id: int, session) -> int:
    """Parse contact from XML element"""
    try:
        # Handle multiple phone numbers and emails
        phone_numbers = safe_get_xml_value(element, ['phone_numbers', 'phones', 'phone'])
        emails = safe_get_xml_value(element, ['emails', 'email', 'email_addresses'])
        
        if isinstance(phone_numbers, str) and phone_numbers:
            phone_numbers = json.dumps([phone_numbers])
        if isinstance(emails, str) and emails:
            emails = json.dumps([emails])
        
        contact = Contact(
            case_id=case_id,
            name=safe_get_xml_value(element, ['name', 'display_name', 'contact_name']),
            phone_numbers=phone_numbers,
            emails=emails,
            organization=safe_get_xml_value(element, ['organization', 'company', 'org']),
            notes=safe_get_xml_value(element, ['notes', 'description', 'comment']),
            created_at=parse_timestamp(safe_get_xml_value(element, ['created_at', 'created'])),
            updated_at=parse_timestamp(safe_get_xml_value(element, ['updated_at', 'modified']))
        )
        
        session.add(contact)
        return 1
        
    except Exception as e:
        logger.warning(f"Failed to parse contact XML: {e}")
        return 0

def parse_media_xml(element, case_id: int, session) -> int:
    """Parse media metadata from XML element"""
    try:
        media = Media(
            case_id=case_id,
            file_name=safe_get_xml_value(element, ['file_name', 'filename', 'name']),
            file_path=safe_get_xml_value(element, ['file_path', 'path', 'location']),
            file_type=safe_get_xml_value(element, ['file_type', 'type', 'format']),
            file_size=safe_get_int(safe_get_xml_value(element, ['file_size', 'size'])),
            hash_md5=safe_get_xml_value(element, ['hash_md5', 'md5']),
            hash_sha256=safe_get_xml_value(element, ['hash_sha256', 'sha256']),
            timestamp=parse_timestamp(safe_get_xml_value(element, ['timestamp', 'date_taken', 'created'])),
            coordinates=safe_get_xml_value(element, ['coordinates', 'gps_coordinates', 'location']),
            camera_make=safe_get_xml_value(element, ['camera_make', 'make']),
            camera_model=safe_get_xml_value(element, ['camera_model', 'model']),
            exif_data=safe_get_xml_value(element, ['exif_data', 'exif', 'metadata'])
        )
        
        session.add(media)
        return 1
        
    except Exception as e:
        logger.warning(f"Failed to parse media XML: {e}")
        return 0

def parse_location_xml(element, case_id: int, session) -> int:
    """Parse location data from XML element"""
    try:
        location = Location(
            case_id=case_id,
            timestamp=parse_timestamp(safe_get_xml_value(element, ['timestamp', 'date', 'time'])),
            latitude=safe_get_float(safe_get_xml_value(element, ['latitude', 'lat'])),
            longitude=safe_get_float(safe_get_xml_value(element, ['longitude', 'lng', 'lon'])),
            altitude=safe_get_float(safe_get_xml_value(element, ['altitude', 'alt'])),
            accuracy=safe_get_float(safe_get_xml_value(element, ['accuracy', 'precision'])),
            source=safe_get_xml_value(element, ['source', 'provider', 'method']),
            activity=safe_get_xml_value(element, ['activity', 'motion', 'state'])
        )
        
        session.add(location)
        return 1
        
    except Exception as e:
        logger.warning(f"Failed to parse location XML: {e}")
        return 0

# SQLite table detection and parsing
def detect_chat_table(table_name: str, columns: List[str]) -> bool:
    """Detect if SQLite table contains chat messages"""
    name_indicators = ['message', 'chat', 'sms', 'conversation']
    column_indicators = ['message', 'content', 'text', 'sender', 'recipient']
    
    return (any(indicator in table_name.lower() for indicator in name_indicators) or
            any(indicator in ' '.join(columns) for indicator in column_indicators))

def detect_call_table(table_name: str, columns: List[str]) -> bool:
    """Detect if SQLite table contains call logs"""
    name_indicators = ['call', 'phone', 'log']
    column_indicators = ['phone_number', 'call_type', 'duration', 'direction']
    
    return (any(indicator in table_name.lower() for indicator in name_indicators) or
            any(indicator in ' '.join(columns) for indicator in column_indicators))

def detect_contact_table(table_name: str, columns: List[str]) -> bool:
    """Detect if SQLite table contains contacts"""
    name_indicators = ['contact', 'address_book', 'phonebook']
    column_indicators = ['name', 'phone', 'email', 'contact']
    
    return (any(indicator in table_name.lower() for indicator in name_indicators) or
            any(indicator in ' '.join(columns) for indicator in column_indicators))

def detect_media_table(table_name: str, columns: List[str]) -> bool:
    """Detect if SQLite table contains media metadata"""
    name_indicators = ['media', 'file', 'image', 'video', 'photo']
    column_indicators = ['file_name', 'file_path', 'file_type', 'exif']
    
    return (any(indicator in table_name.lower() for indicator in name_indicators) or
            any(indicator in ' '.join(columns) for indicator in column_indicators))

def detect_location_table(table_name: str, columns: List[str]) -> bool:
    """Detect if SQLite table contains location data"""
    name_indicators = ['location', 'gps', 'coordinate', 'position']
    column_indicators = ['latitude', 'longitude', 'coordinates', 'gps']
    
    return (any(indicator in table_name.lower() for indicator in name_indicators) or
            any(indicator in ' '.join(columns) for indicator in column_indicators))

# SQLite table parsing functions
def parse_chat_table_sqlite(cursor, table_name: str, case_id: int, session) -> int:
    """Parse chat messages from SQLite table"""
    count = 0
    
    try:
        cursor.execute(f"SELECT * FROM {table_name}")
        rows = cursor.fetchall()
        
        for row in rows:
            try:
                row_dict = dict(row)
                message = ChatMessage(
                    case_id=case_id,
                    chat_id=safe_get_dict_value(row_dict, ['chat_id', 'conversation_id', 'thread_id']),
                    app_name=safe_get_dict_value(row_dict, ['app_name', 'application', 'source']),
                    sender=safe_get_dict_value(row_dict, ['sender', 'from', 'author']),
                    recipient=safe_get_dict_value(row_dict, ['recipient', 'to', 'receiver']),
                    content=safe_get_dict_value(row_dict, ['content', 'message', 'text', 'body']),
                    timestamp=parse_timestamp(safe_get_dict_value(row_dict, ['timestamp', 'date', 'time'])),
                    direction=safe_get_dict_value(row_dict, ['direction', 'type']),
                    message_type=safe_get_dict_value(row_dict, ['message_type', 'msg_type', 'type']),
                    coordinates=safe_get_dict_value(row_dict, ['coordinates', 'location', 'gps'])
                )
                
                session.add(message)
                count += 1
                
            except Exception as e:
                logger.warning(f"Failed to parse chat message row from SQLite: {e}")
                continue
    
    except Exception as e:
        logger.error(f"Error querying SQLite table {table_name}: {e}")
    
    return count

def parse_call_table_sqlite(cursor, table_name: str, case_id: int, session) -> int:
    """Parse call logs from SQLite table"""
    count = 0
    
    try:
        cursor.execute(f"SELECT * FROM {table_name}")
        rows = cursor.fetchall()
        
        for row in rows:
            try:
                row_dict = dict(row)
                call = Call(
                    case_id=case_id,
                    phone_number=safe_get_dict_value(row_dict, ['phone_number', 'number', 'phone']),
                    contact_name=safe_get_dict_value(row_dict, ['contact_name', 'name', 'contact']),
                    call_type=safe_get_dict_value(row_dict, ['call_type', 'type']),
                    direction=safe_get_dict_value(row_dict, ['direction', 'call_direction']),
                    timestamp=parse_timestamp(safe_get_dict_value(row_dict, ['timestamp', 'date', 'time'])),
                    duration=safe_get_int(safe_get_dict_value(row_dict, ['duration', 'call_duration'])),
                    coordinates=safe_get_dict_value(row_dict, ['coordinates', 'location', 'gps']),
                    cell_tower=safe_get_dict_value(row_dict, ['cell_tower', 'tower_id', 'cell_id'])
                )
                
                session.add(call)
                count += 1
                
            except Exception as e:
                logger.warning(f"Failed to parse call log row from SQLite: {e}")
                continue
    
    except Exception as e:
        logger.error(f"Error querying SQLite table {table_name}: {e}")
    
    return count

def parse_contact_table_sqlite(cursor, table_name: str, case_id: int, session) -> int:
    """Parse contacts from SQLite table"""
    count = 0
    
    try:
        cursor.execute(f"SELECT * FROM {table_name}")
        rows = cursor.fetchall()
        
        for row in rows:
            try:
                row_dict = dict(row)
                
                # Handle multiple phone numbers and emails
                phone_numbers = safe_get_dict_value(row_dict, ['phone_numbers', 'phones', 'phone'])
                emails = safe_get_dict_value(row_dict, ['emails', 'email', 'email_addresses'])
                
                if isinstance(phone_numbers, str) and phone_numbers:
                    phone_numbers = json.dumps([phone_numbers])
                if isinstance(emails, str) and emails:
                    emails = json.dumps([emails])
                
                contact = Contact(
                    case_id=case_id,
                    name=safe_get_dict_value(row_dict, ['name', 'display_name', 'contact_name']),
                    phone_numbers=phone_numbers,
                    emails=emails,
                    organization=safe_get_dict_value(row_dict, ['organization', 'company', 'org']),
                    notes=safe_get_dict_value(row_dict, ['notes', 'description', 'comment']),
                    created_at=parse_timestamp(safe_get_dict_value(row_dict, ['created_at', 'created'])),
                    updated_at=parse_timestamp(safe_get_dict_value(row_dict, ['updated_at', 'modified']))
                )
                
                session.add(contact)
                count += 1
                
            except Exception as e:
                logger.warning(f"Failed to parse contact row from SQLite: {e}")
                continue
    
    except Exception as e:
        logger.error(f"Error querying SQLite table {table_name}: {e}")
    
    return count

def parse_media_table_sqlite(cursor, table_name: str, case_id: int, session) -> int:
    """Parse media metadata from SQLite table"""
    count = 0
    
    try:
        cursor.execute(f"SELECT * FROM {table_name}")
        rows = cursor.fetchall()
        
        for row in rows:
            try:
                row_dict = dict(row)
                media = Media(
                    case_id=case_id,
                    file_name=safe_get_dict_value(row_dict, ['file_name', 'filename', 'name']),
                    file_path=safe_get_dict_value(row_dict, ['file_path', 'path', 'location']),
                    file_type=safe_get_dict_value(row_dict, ['file_type', 'type', 'format']),
                    file_size=safe_get_int(safe_get_dict_value(row_dict, ['file_size', 'size'])),
                    hash_md5=safe_get_dict_value(row_dict, ['hash_md5', 'md5']),
                    hash_sha256=safe_get_dict_value(row_dict, ['hash_sha256', 'sha256']),
                    timestamp=parse_timestamp(safe_get_dict_value(row_dict, ['timestamp', 'date_taken', 'created'])),
                    coordinates=safe_get_dict_value(row_dict, ['coordinates', 'gps_coordinates', 'location']),
                    camera_make=safe_get_dict_value(row_dict, ['camera_make', 'make']),
                    camera_model=safe_get_dict_value(row_dict, ['camera_model', 'model']),
                    exif_data=safe_get_dict_value(row_dict, ['exif_data', 'exif', 'metadata'])
                )
                
                session.add(media)
                count += 1
                
            except Exception as e:
                logger.warning(f"Failed to parse media row from SQLite: {e}")
                continue
    
    except Exception as e:
        logger.error(f"Error querying SQLite table {table_name}: {e}")
    
    return count

def parse_location_table_sqlite(cursor, table_name: str, case_id: int, session) -> int:
    """Parse location data from SQLite table"""
    count = 0
    
    try:
        cursor.execute(f"SELECT * FROM {table_name}")
        rows = cursor.fetchall()
        
        for row in rows:
            try:
                row_dict = dict(row)
                location = Location(
                    case_id=case_id,
                    timestamp=parse_timestamp(safe_get_dict_value(row_dict, ['timestamp', 'date', 'time'])),
                    latitude=safe_get_float(safe_get_dict_value(row_dict, ['latitude', 'lat'])),
                    longitude=safe_get_float(safe_get_dict_value(row_dict, ['longitude', 'lng', 'lon'])),
                    altitude=safe_get_float(safe_get_dict_value(row_dict, ['altitude', 'alt'])),
                    accuracy=safe_get_float(safe_get_dict_value(row_dict, ['accuracy', 'precision'])),
                    source=safe_get_dict_value(row_dict, ['source', 'provider', 'method']),
                    activity=safe_get_dict_value(row_dict, ['activity', 'motion', 'state'])
                )
                
                session.add(location)
                count += 1
                
            except Exception as e:
                logger.warning(f"Failed to parse location row from SQLite: {e}")
                continue
    
    except Exception as e:
        logger.error(f"Error querying SQLite table {table_name}: {e}")
    
    return count

# Utility functions
def safe_get_value(row, keys: List[str]) -> Optional[str]:
    """Safely get value from pandas row using multiple possible keys"""
    for key in keys:
        for col in row.index:
            if key.lower() in col.lower():
                value = row[col]
                if pd.notna(value) and str(value).strip():
                    return str(value).strip()
    return None

def safe_get_dict_value(data: dict, keys: List[str]) -> Optional[str]:
    """Safely get value from dictionary using multiple possible keys"""
    for key in keys:
        for data_key in data.keys():
            if key.lower() in data_key.lower():
                value = data[data_key]
                if value is not None and str(value).strip():
                    return str(value).strip()
    return None

def safe_get_xml_value(element, keys: List[str]) -> Optional[str]:
    """Safely get value from XML element using multiple possible keys"""
    # Try as attributes first
    for key in keys:
        for attr_key in element.attrib:
            if key.lower() in attr_key.lower():
                return element.attrib[attr_key]
    
    # Try as child elements
    for key in keys:
        for child in element:
            if key.lower() in child.tag.lower():
                return child.text
    
    # Try direct text content
    if element.text and element.text.strip():
        return element.text.strip()
    
    return None

def safe_get_int(value) -> Optional[int]:
    """Safely convert value to integer"""
    if value is None:
        return None
    try:
        return int(float(str(value)))
    except (ValueError, TypeError):
        return None

def safe_get_float(value) -> Optional[float]:
    """Safely convert value to float"""
    if value is None:
        return None
    try:
        return float(str(value))
    except (ValueError, TypeError):
        return None

def parse_timestamp(value) -> Optional[datetime]:
    """Parse timestamp from various formats"""
    if value is None or str(value).strip() == '':
        return None
    
    try:
        # Common timestamp formats
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y/%m/%d %H:%M:%S',
            '%d/%m/%Y %H:%M:%S',
            '%m/%d/%Y %H:%M:%S',
            '%Y-%m-%d',
            '%d/%m/%Y',
            '%m/%d/%Y'
        ]
        
        value_str = str(value).strip()
        
        # Try Unix timestamp
        try:
            if value_str.isdigit():
                timestamp = int(value_str)
                if timestamp > 1000000000:  # Unix timestamp in seconds
                    return datetime.fromtimestamp(timestamp)
                elif timestamp > 1000000000000:  # Unix timestamp in milliseconds
                    return datetime.fromtimestamp(timestamp / 1000)
        except:
            pass
        
        # Try various datetime formats
        for fmt in formats:
            try:
                return datetime.strptime(value_str, fmt)
            except ValueError:
                continue
        
        # Try pandas to_datetime as fallback
        try:
            return pd.to_datetime(value_str).to_pydatetime()
        except:
            pass
        
    except Exception as e:
        logger.warning(f"Failed to parse timestamp '{value}': {e}")
    
    return None
