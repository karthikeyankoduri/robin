import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from sqlalchemy import or_, and_, func, text
from utils.db import get_db_session, ChatMessage, Call, Contact, Media, Location, Case

logger = logging.getLogger(__name__)

@dataclass
class SearchFilters:
    """Search filter configuration"""
    case_id: Optional[int] = None
    search_type: str = "All Data"
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    include_deleted: bool = False
    media_only: bool = False
    sender_filter: Optional[str] = None
    recipient_filter: Optional[str] = None
    app_filter: Optional[str] = None

class SearchEngine:
    """Advanced search engine for forensic data"""
    
    def __init__(self):
        self.session = None
    
    def __enter__(self):
        self.session = get_db_session()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            self.session.close()

def perform_full_text_search(query: str, filters: SearchFilters) -> List[Dict[str, Any]]:
    """
    Perform comprehensive full-text search across all data types
    
    Args:
        query: Search query string
        filters: Search filters and constraints
    
    Returns:
        List of search results with metadata
    """
    try:
        with SearchEngine() as search_engine:
            results = []
            
            # Parse query for advanced search features
            parsed_query = parse_search_query(query)
            
            # Search different data types based on filters
            if filters.search_type in ["All Data", "Chat Messages"]:
                message_results = search_chat_messages(search_engine.session, parsed_query, filters)
                results.extend(message_results)
            
            if filters.search_type in ["All Data", "Call Logs"]:
                call_results = search_call_logs(search_engine.session, parsed_query, filters)
                results.extend(call_results)
            
            if filters.search_type in ["All Data", "Contacts"]:
                contact_results = search_contacts(search_engine.session, parsed_query, filters)
                results.extend(contact_results)
            
            if filters.search_type in ["All Data", "Media"]:
                media_results = search_media(search_engine.session, parsed_query, filters)
                results.extend(media_results)
            
            if filters.search_type in ["All Data", "Locations"]:
                location_results = search_locations(search_engine.session, parsed_query, filters)
                results.extend(location_results)
            
            # Sort results by relevance and timestamp
            results = sort_search_results(results, parsed_query)
            
            return results
    
    except Exception as e:
        logger.error(f"Full-text search error: {e}")
        return []

def parse_search_query(query: str) -> Dict[str, Any]:
    """
    Parse search query to extract advanced search features
    
    Args:
        query: Raw search query
    
    Returns:
        Parsed query information
    """
    try:
        parsed = {
            'original_query': query,
            'terms': [],
            'phrases': [],
            'exclude_terms': [],
            'phone_numbers': [],
            'email_addresses': [],
            'dates': [],
            'operators': []
        }
        
        if not query or not query.strip():
            return parsed
        
        query = query.strip()
        
        # Extract quoted phrases
        phrase_pattern = r'"([^"]*)"'
        phrases = re.findall(phrase_pattern, query)
        parsed['phrases'] = [phrase.strip() for phrase in phrases if phrase.strip()]
        
        # Remove phrases from query for further processing
        query_without_phrases = re.sub(phrase_pattern, '', query)
        
        # Extract exclusion terms (terms starting with -)
        exclude_pattern = r'-(\w+)'
        exclude_terms = re.findall(exclude_pattern, query_without_phrases)
        parsed['exclude_terms'] = exclude_terms
        
        # Remove exclusion terms
        query_without_excludes = re.sub(exclude_pattern, '', query_without_phrases)
        
        # Extract phone numbers
        phone_patterns = [
            r'\b\d{3}-\d{3}-\d{4}\b',  # XXX-XXX-XXXX
            r'\b\(\d{3}\)\s*\d{3}-\d{4}\b',  # (XXX) XXX-XXXX
            r'\b\d{3}\.\d{3}\.\d{4}\b',  # XXX.XXX.XXXX
            r'\b\d{10}\b',  # XXXXXXXXXX
            r'\+\d{1,3}\s*\d{3,4}\s*\d{3,4}\s*\d{3,4}',  # International
        ]
        
        for pattern in phone_patterns:
            phones = re.findall(pattern, query)
            parsed['phone_numbers'].extend(phones)
        
        # Extract email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, query)
        parsed['email_addresses'] = emails
        
        # Extract dates (basic patterns)
        date_patterns = [
            r'\b\d{4}-\d{2}-\d{2}\b',  # YYYY-MM-DD
            r'\b\d{2}/\d{2}/\d{4}\b',  # MM/DD/YYYY
            r'\b\d{2}-\d{2}-\d{4}\b',  # MM-DD-YYYY
        ]
        
        for pattern in date_patterns:
            dates = re.findall(pattern, query)
            parsed['dates'].extend(dates)
        
        # Extract Boolean operators
        if 'AND' in query.upper():
            parsed['operators'].append('AND')
        if 'OR' in query.upper():
            parsed['operators'].append('OR')
        if 'NOT' in query.upper():
            parsed['operators'].append('NOT')
        
        # Extract remaining terms
        remaining_query = query_without_excludes
        for phone in parsed['phone_numbers']:
            remaining_query = remaining_query.replace(phone, '')
        for email in parsed['email_addresses']:
            remaining_query = remaining_query.replace(email, '')
        for date in parsed['dates']:
            remaining_query = remaining_query.replace(date, '')
        
        # Clean up and extract terms
        remaining_query = re.sub(r'\b(AND|OR|NOT)\b', '', remaining_query, flags=re.IGNORECASE)
        terms = [term.strip() for term in remaining_query.split() if term.strip() and len(term.strip()) > 1]
        parsed['terms'] = terms
        
        return parsed
    
    except Exception as e:
        logger.error(f"Query parsing error: {e}")
        return {'original_query': query, 'terms': [query], 'phrases': [], 'exclude_terms': [], 
                'phone_numbers': [], 'email_addresses': [], 'dates': [], 'operators': []}

def search_chat_messages(session, parsed_query: Dict[str, Any], filters: SearchFilters) -> List[Dict[str, Any]]:
    """Search chat messages with advanced filtering"""
    try:
        results = []
        
        # Build base query
        query = session.query(ChatMessage)
        
        # Apply case filter
        if filters.case_id:
            query = query.filter(ChatMessage.case_id == filters.case_id)
        
        # Apply date filters
        if filters.start_date:
            query = query.filter(ChatMessage.timestamp >= filters.start_date)
        if filters.end_date:
            query = query.filter(ChatMessage.timestamp <= filters.end_date)
        
        # Apply app filter
        if filters.app_filter:
            query = query.filter(ChatMessage.app_name.ilike(f"%{filters.app_filter}%"))
        
        # Apply sender/recipient filters
        if filters.sender_filter:
            query = query.filter(ChatMessage.sender.ilike(f"%{filters.sender_filter}%"))
        if filters.recipient_filter:
            query = query.filter(ChatMessage.recipient.ilike(f"%{filters.recipient_filter}%"))
        
        # Include deleted messages filter
        if not filters.include_deleted:
            query = query.filter(ChatMessage.is_deleted == False)
        
        # Build text search conditions
        search_conditions = []
        
        # Search in content
        if parsed_query['terms']:
            for term in parsed_query['terms']:
                search_conditions.append(ChatMessage.content.ilike(f"%{term}%"))
        
        if parsed_query['phrases']:
            for phrase in parsed_query['phrases']:
                search_conditions.append(ChatMessage.content.ilike(f"%{phrase}%"))
        
        # Search phone numbers in content and sender/recipient
        if parsed_query['phone_numbers']:
            for phone in parsed_query['phone_numbers']:
                search_conditions.extend([
                    ChatMessage.content.ilike(f"%{phone}%"),
                    ChatMessage.sender.ilike(f"%{phone}%"),
                    ChatMessage.recipient.ilike(f"%{phone}%")
                ])
        
        # Search email addresses
        if parsed_query['email_addresses']:
            for email in parsed_query['email_addresses']:
                search_conditions.extend([
                    ChatMessage.content.ilike(f"%{email}%"),
                    ChatMessage.sender.ilike(f"%{email}%"),
                    ChatMessage.recipient.ilike(f"%{email}%")
                ])
        
        # Apply search conditions
        if search_conditions:
            if 'AND' in parsed_query['operators']:
                query = query.filter(and_(*search_conditions))
            else:
                query = query.filter(or_(*search_conditions))
        
        # Apply exclusion terms
        if parsed_query['exclude_terms']:
            for exclude_term in parsed_query['exclude_terms']:
                query = query.filter(~ChatMessage.content.ilike(f"%{exclude_term}%"))
        
        # Execute query
        messages = query.order_by(ChatMessage.timestamp.desc()).limit(500).all()
        
        # Format results
        for msg in messages:
            result = {
                'type': 'ChatMessage',
                'id': msg.id,
                'title': f"Message from {msg.sender or 'Unknown'}",
                'content': msg.content or '',
                'sender': msg.sender,
                'recipient': msg.recipient,
                'timestamp': msg.timestamp,
                'app_name': msg.app_name,
                'chat_id': msg.chat_id,
                'direction': msg.direction,
                'message_type': msg.message_type,
                'coordinates': msg.coordinates,
                'case_id': msg.case_id,
                'relevance_score': calculate_relevance_score(msg.content or '', parsed_query)
            }
            results.append(result)
        
        return results
    
    except Exception as e:
        logger.error(f"Chat message search error: {e}")
        return []

def search_call_logs(session, parsed_query: Dict[str, Any], filters: SearchFilters) -> List[Dict[str, Any]]:
    """Search call logs with advanced filtering"""
    try:
        results = []
        
        # Build base query
        query = session.query(Call)
        
        # Apply case filter
        if filters.case_id:
            query = query.filter(Call.case_id == filters.case_id)
        
        # Apply date filters
        if filters.start_date:
            query = query.filter(Call.timestamp >= filters.start_date)
        if filters.end_date:
            query = query.filter(Call.timestamp <= filters.end_date)
        
        # Build search conditions
        search_conditions = []
        
        # Search in phone numbers and contact names
        if parsed_query['terms']:
            for term in parsed_query['terms']:
                search_conditions.extend([
                    Call.phone_number.ilike(f"%{term}%"),
                    Call.contact_name.ilike(f"%{term}%")
                ])
        
        # Search phone numbers specifically
        if parsed_query['phone_numbers']:
            for phone in parsed_query['phone_numbers']:
                search_conditions.append(Call.phone_number.ilike(f"%{phone}%"))
        
        # Apply search conditions
        if search_conditions:
            query = query.filter(or_(*search_conditions))
        
        # Execute query
        calls = query.order_by(Call.timestamp.desc()).limit(500).all()
        
        # Format results
        for call in calls:
            result = {
                'type': 'Call',
                'id': call.id,
                'title': f"Call {call.direction or 'Unknown'} - {call.phone_number or 'Unknown'}",
                'phone_number': call.phone_number,
                'contact_name': call.contact_name,
                'timestamp': call.timestamp,
                'call_type': call.call_type,
                'direction': call.direction,
                'duration': call.duration,
                'coordinates': call.coordinates,
                'cell_tower': call.cell_tower,
                'case_id': call.case_id,
                'relevance_score': calculate_relevance_score(f"{call.phone_number} {call.contact_name}", parsed_query)
            }
            results.append(result)
        
        return results
    
    except Exception as e:
        logger.error(f"Call log search error: {e}")
        return []

def search_contacts(session, parsed_query: Dict[str, Any], filters: SearchFilters) -> List[Dict[str, Any]]:
    """Search contacts with advanced filtering"""
    try:
        results = []
        
        # Build base query
        query = session.query(Contact)
        
        # Apply case filter
        if filters.case_id:
            query = query.filter(Contact.case_id == filters.case_id)
        
        # Build search conditions
        search_conditions = []
        
        # Search in names, phone numbers, emails, organizations, and notes
        if parsed_query['terms']:
            for term in parsed_query['terms']:
                search_conditions.extend([
                    Contact.name.ilike(f"%{term}%"),
                    Contact.phone_numbers.ilike(f"%{term}%"),
                    Contact.emails.ilike(f"%{term}%"),
                    Contact.organization.ilike(f"%{term}%"),
                    Contact.notes.ilike(f"%{term}%")
                ])
        
        # Search phrases
        if parsed_query['phrases']:
            for phrase in parsed_query['phrases']:
                search_conditions.extend([
                    Contact.name.ilike(f"%{phrase}%"),
                    Contact.notes.ilike(f"%{phrase}%")
                ])
        
        # Search phone numbers
        if parsed_query['phone_numbers']:
            for phone in parsed_query['phone_numbers']:
                search_conditions.append(Contact.phone_numbers.ilike(f"%{phone}%"))
        
        # Search email addresses
        if parsed_query['email_addresses']:
            for email in parsed_query['email_addresses']:
                search_conditions.append(Contact.emails.ilike(f"%{email}%"))
        
        # Apply search conditions
        if search_conditions:
            query = query.filter(or_(*search_conditions))
        
        # Execute query
        contacts = query.limit(500).all()
        
        # Format results
        for contact in contacts:
            result = {
                'type': 'Contact',
                'id': contact.id,
                'title': f"Contact: {contact.name or 'Unknown'}",
                'name': contact.name,
                'phone_numbers': contact.phone_numbers,
                'emails': contact.emails,
                'organization': contact.organization,
                'notes': contact.notes,
                'created_at': contact.created_at,
                'updated_at': contact.updated_at,
                'case_id': contact.case_id,
                'relevance_score': calculate_relevance_score(f"{contact.name} {contact.notes}", parsed_query)
            }
            results.append(result)
        
        return results
    
    except Exception as e:
        logger.error(f"Contact search error: {e}")
        return []

def search_media(session, parsed_query: Dict[str, Any], filters: SearchFilters) -> List[Dict[str, Any]]:
    """Search media files with advanced filtering"""
    try:
        results = []
        
        # Build base query
        query = session.query(Media)
        
        # Apply case filter
        if filters.case_id:
            query = query.filter(Media.case_id == filters.case_id)
        
        # Apply date filters
        if filters.start_date:
            query = query.filter(Media.timestamp >= filters.start_date)
        if filters.end_date:
            query = query.filter(Media.timestamp <= filters.end_date)
        
        # Build search conditions
        search_conditions = []
        
        # Search in file names, paths, and EXIF data
        if parsed_query['terms']:
            for term in parsed_query['terms']:
                search_conditions.extend([
                    Media.file_name.ilike(f"%{term}%"),
                    Media.file_path.ilike(f"%{term}%"),
                    Media.camera_make.ilike(f"%{term}%"),
                    Media.camera_model.ilike(f"%{term}%"),
                    Media.exif_data.ilike(f"%{term}%")
                ])
        
        # Apply search conditions
        if search_conditions:
            query = query.filter(or_(*search_conditions))
        
        # Execute query
        media_files = query.order_by(Media.timestamp.desc()).limit(500).all()
        
        # Format results
        for media in media_files:
            result = {
                'type': 'Media',
                'id': media.id,
                'title': f"Media: {media.file_name or 'Unknown'}",
                'file_name': media.file_name,
                'file_path': media.file_path,
                'file_type': media.file_type,
                'file_size': media.file_size,
                'timestamp': media.timestamp,
                'coordinates': media.coordinates,
                'camera_make': media.camera_make,
                'camera_model': media.camera_model,
                'hash_md5': media.hash_md5,
                'hash_sha256': media.hash_sha256,
                'case_id': media.case_id,
                'relevance_score': calculate_relevance_score(f"{media.file_name} {media.camera_make}", parsed_query)
            }
            results.append(result)
        
        return results
    
    except Exception as e:
        logger.error(f"Media search error: {e}")
        return []

def search_locations(session, parsed_query: Dict[str, Any], filters: SearchFilters) -> List[Dict[str, Any]]:
    """Search location data with advanced filtering"""
    try:
        results = []
        
        # Build base query
        query = session.query(Location)
        
        # Apply case filter
        if filters.case_id:
            query = query.filter(Location.case_id == filters.case_id)
        
        # Apply date filters
        if filters.start_date:
            query = query.filter(Location.timestamp >= filters.start_date)
        if filters.end_date:
            query = query.filter(Location.timestamp <= filters.end_date)
        
        # Build search conditions
        search_conditions = []
        
        # Search in source and activity fields
        if parsed_query['terms']:
            for term in parsed_query['terms']:
                search_conditions.extend([
                    Location.source.ilike(f"%{term}%"),
                    Location.activity.ilike(f"%{term}%")
                ])
        
        # Apply search conditions
        if search_conditions:
            query = query.filter(or_(*search_conditions))
        
        # Execute query
        locations = query.order_by(Location.timestamp.desc()).limit(500).all()
        
        # Format results
        for location in locations:
            result = {
                'type': 'Location',
                'id': location.id,
                'title': f"Location: {location.latitude:.6f}, {location.longitude:.6f}",
                'coordinates': f"{location.latitude:.6f}, {location.longitude:.6f}",
                'latitude': location.latitude,
                'longitude': location.longitude,
                'altitude': location.altitude,
                'accuracy': location.accuracy,
                'timestamp': location.timestamp,
                'source': location.source,
                'activity': location.activity,
                'case_id': location.case_id,
                'relevance_score': calculate_relevance_score(f"{location.source} {location.activity}", parsed_query)
            }
            results.append(result)
        
        return results
    
    except Exception as e:
        logger.error(f"Location search error: {e}")
        return []

def calculate_relevance_score(text: str, parsed_query: Dict[str, Any]) -> float:
    """Calculate relevance score for search result"""
    try:
        if not text:
            return 0.0
        
        text_lower = text.lower()
        score = 0.0
        
        # Score for exact phrase matches (highest weight)
        for phrase in parsed_query['phrases']:
            if phrase.lower() in text_lower:
                score += 10.0
        
        # Score for individual term matches
        for term in parsed_query['terms']:
            if term.lower() in text_lower:
                score += 5.0
        
        # Score for phone number matches
        for phone in parsed_query['phone_numbers']:
            if phone in text:
                score += 8.0
        
        # Score for email matches
        for email in parsed_query['email_addresses']:
            if email.lower() in text_lower:
                score += 8.0
        
        # Normalize score based on text length
        if len(text) > 0:
            score = score / (len(text) / 100)  # Normalize by text length
        
        return min(100.0, score)  # Cap at 100
    
    except Exception as e:
        logger.error(f"Relevance scoring error: {e}")
        return 0.0

def sort_search_results(results: List[Dict[str, Any]], parsed_query: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Sort search results by relevance and recency"""
    try:
        def sort_key(result):
            relevance = result.get('relevance_score', 0.0)
            
            # Time-based scoring (more recent = higher score)
            timestamp = result.get('timestamp')
            time_score = 0.0
            if timestamp:
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                
                days_old = (datetime.utcnow() - timestamp.replace(tzinfo=None)).days
                time_score = max(0, 10 - (days_old / 30))  # Decay over 30 days
            
            # Combine relevance and time scores
            combined_score = relevance + time_score
            
            return (-combined_score, result.get('timestamp', datetime.min))
        
        return sorted(results, key=sort_key)
    
    except Exception as e:
        logger.error(f"Result sorting error: {e}")
        return results

def search_similar_content(session, reference_text: str, case_id: int = None, similarity_threshold: float = 0.7) -> List[Dict[str, Any]]:
    """Find content similar to reference text using fuzzy matching"""
    try:
        from difflib import SequenceMatcher
        
        results = []
        
        # Search in chat messages
        messages_query = session.query(ChatMessage)
        if case_id:
            messages_query = messages_query.filter(ChatMessage.case_id == case_id)
        
        messages = messages_query.filter(ChatMessage.content.isnot(None)).all()
        
        for msg in messages:
            if msg.content:
                similarity = SequenceMatcher(None, reference_text.lower(), msg.content.lower()).ratio()
                if similarity >= similarity_threshold:
                    results.append({
                        'type': 'ChatMessage',
                        'id': msg.id,
                        'content': msg.content,
                        'sender': msg.sender,
                        'timestamp': msg.timestamp,
                        'similarity_score': similarity,
                        'case_id': msg.case_id
                    })
        
        # Sort by similarity score
        results.sort(key=lambda x: x['similarity_score'], reverse=True)
        
        return results[:50]  # Return top 50 similar results
    
    except Exception as e:
        logger.error(f"Similar content search error: {e}")
        return []

def search_time_range_activity(session, start_time: datetime, end_time: datetime, case_id: int = None) -> Dict[str, List]:
    """Search for all activity within a specific time range"""
    try:
        activity = {
            'messages': [],
            'calls': [],
            'media': [],
            'locations': []
        }
        
        # Messages
        messages_query = session.query(ChatMessage).filter(
            ChatMessage.timestamp >= start_time,
            ChatMessage.timestamp <= end_time
        )
        if case_id:
            messages_query = messages_query.filter(ChatMessage.case_id == case_id)
        
        for msg in messages_query.all():
            activity['messages'].append({
                'id': msg.id,
                'timestamp': msg.timestamp,
                'sender': msg.sender,
                'content': msg.content[:100] + '...' if msg.content and len(msg.content) > 100 else msg.content,
                'app_name': msg.app_name
            })
        
        # Calls
        calls_query = session.query(Call).filter(
            Call.timestamp >= start_time,
            Call.timestamp <= end_time
        )
        if case_id:
            calls_query = calls_query.filter(Call.case_id == case_id)
        
        for call in calls_query.all():
            activity['calls'].append({
                'id': call.id,
                'timestamp': call.timestamp,
                'phone_number': call.phone_number,
                'direction': call.direction,
                'duration': call.duration,
                'call_type': call.call_type
            })
        
        # Media
        media_query = session.query(Media).filter(
            Media.timestamp >= start_time,
            Media.timestamp <= end_time
        )
        if case_id:
            media_query = media_query.filter(Media.case_id == case_id)
        
        for media in media_query.all():
            activity['media'].append({
                'id': media.id,
                'timestamp': media.timestamp,
                'file_name': media.file_name,
                'file_type': media.file_type,
                'coordinates': media.coordinates
            })
        
        # Locations
        locations_query = session.query(Location).filter(
            Location.timestamp >= start_time,
            Location.timestamp <= end_time
        )
        if case_id:
            locations_query = locations_query.filter(Location.case_id == case_id)
        
        for location in locations_query.all():
            activity['locations'].append({
                'id': location.id,
                'timestamp': location.timestamp,
                'latitude': location.latitude,
                'longitude': location.longitude,
                'source': location.source,
                'activity': location.activity
            })
        
        return activity
    
    except Exception as e:
        logger.error(f"Time range activity search error: {e}")
        return {'messages': [], 'calls': [], 'media': [], 'locations': []}

def search_geolocation(session, latitude: float, longitude: float, radius_km: float = 1.0, case_id: int = None) -> List[Dict[str, Any]]:
    """Search for data within a geographic radius"""
    try:
        results = []
        
        # Calculate approximate lat/lng bounds for the radius
        # This is a simplified calculation - for production use PostGIS or similar
        lat_degree_km = 111.0  # Approximate km per degree latitude
        lng_degree_km = 111.0 * abs(math.cos(math.radians(latitude)))  # Adjust for longitude
        
        lat_delta = radius_km / lat_degree_km
        lng_delta = radius_km / lng_degree_km
        
        min_lat = latitude - lat_delta
        max_lat = latitude + lat_delta
        min_lng = longitude - lng_delta
        max_lng = longitude + lng_delta
        
        # Search locations
        locations_query = session.query(Location).filter(
            Location.latitude >= min_lat,
            Location.latitude <= max_lat,
            Location.longitude >= min_lng,
            Location.longitude <= max_lng
        )
        
        if case_id:
            locations_query = locations_query.filter(Location.case_id == case_id)
        
        for location in locations_query.all():
            # Calculate actual distance
            distance = calculate_distance(latitude, longitude, location.latitude, location.longitude)
            if distance <= radius_km:
                results.append({
                    'type': 'Location',
                    'id': location.id,
                    'timestamp': location.timestamp,
                    'coordinates': f"{location.latitude:.6f}, {location.longitude:.6f}",
                    'distance_km': distance,
                    'source': location.source,
                    'activity': location.activity,
                    'case_id': location.case_id
                })
        
        # Search media with coordinates
        media_query = session.query(Media).filter(Media.coordinates.isnot(None))
        if case_id:
            media_query = media_query.filter(Media.case_id == case_id)
        
        for media in media_query.all():
            if media.coordinates:
                try:
                    # Parse coordinates (assuming "lat,lng" format)
                    coords = media.coordinates.split(',')
                    if len(coords) == 2:
                        media_lat = float(coords[0])
                        media_lng = float(coords[1])
                        
                        if (min_lat <= media_lat <= max_lat and min_lng <= media_lng <= max_lng):
                            distance = calculate_distance(latitude, longitude, media_lat, media_lng)
                            if distance <= radius_km:
                                results.append({
                                    'type': 'Media',
                                    'id': media.id,
                                    'timestamp': media.timestamp,
                                    'file_name': media.file_name,
                                    'coordinates': media.coordinates,
                                    'distance_km': distance,
                                    'case_id': media.case_id
                                })
                except ValueError:
                    continue
        
        # Sort by distance
        results.sort(key=lambda x: x['distance_km'])
        
        return results
    
    except Exception as e:
        logger.error(f"Geolocation search error: {e}")
        return []

def calculate_distance(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """Calculate distance between two coordinates using Haversine formula"""
    try:
        import math
        
        # Convert to radians
        lat1_rad = math.radians(lat1)
        lng1_rad = math.radians(lng1)
        lat2_rad = math.radians(lat2)
        lng2_rad = math.radians(lng2)
        
        # Haversine formula
        dlat = lat2_rad - lat1_rad
        dlng = lng2_rad - lng1_rad
        
        a = math.sin(dlat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlng/2)**2
        c = 2 * math.asin(math.sqrt(a))
        
        # Earth's radius in kilometers
        earth_radius_km = 6371.0
        
        return earth_radius_km * c
    
    except Exception as e:
        logger.error(f"Distance calculation error: {e}")
        return float('inf')

def search_entity_mentions(session, entity_text: str, entity_type: str = None, case_id: int = None) -> List[Dict[str, Any]]:
    """Search for mentions of specific entities across all data types"""
    try:
        results = []
        
        # Search in chat messages
        messages_query = session.query(ChatMessage).filter(
            ChatMessage.content.ilike(f"%{entity_text}%")
        )
        if case_id:
            messages_query = messages_query.filter(ChatMessage.case_id == case_id)
        
        for msg in messages_query.all():
            results.append({
                'type': 'ChatMessage',
                'id': msg.id,
                'content': msg.content,
                'sender': msg.sender,
                'timestamp': msg.timestamp,
                'entity_mentioned': entity_text,
                'entity_type': entity_type,
                'case_id': msg.case_id
            })
        
        # Search in contacts
        contacts_query = session.query(Contact).filter(
            or_(
                Contact.name.ilike(f"%{entity_text}%"),
                Contact.notes.ilike(f"%{entity_text}%"),
                Contact.organization.ilike(f"%{entity_text}%")
            )
        )
        if case_id:
            contacts_query = contacts_query.filter(Contact.case_id == case_id)
        
        for contact in contacts_query.all():
            results.append({
                'type': 'Contact',
                'id': contact.id,
                'name': contact.name,
                'organization': contact.organization,
                'notes': contact.notes,
                'entity_mentioned': entity_text,
                'entity_type': entity_type,
                'case_id': contact.case_id
            })
        
        return results
    
    except Exception as e:
        logger.error(f"Entity mention search error: {e}")
        return []

def create_search_index(session):
    """Create search indexes for better performance (database-specific)"""
    try:
        # This would create full-text search indexes
        # Implementation depends on the database system
        # For PostgreSQL, this might use GIN indexes
        # For SQLite, this might use FTS extensions
        
        logger.info("Search indexes would be created here for production deployment")
        return True
    
    except Exception as e:
        logger.error(f"Search index creation error: {e}")
        return False
