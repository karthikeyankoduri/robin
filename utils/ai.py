import os
import json
import spacy
from typing import List, Dict, Any, Optional
import logging
from google import genai
from google.genai import types

# Configure logging
logger = logging.getLogger(__name__)

# Initialize Google Gemini client
# IMPORTANT: Follow the Gemini integration blueprint
# Note that the newest Gemini model series is "gemini-2.5-flash" or "gemini-2.5-pro"
# do not change this unless explicitly requested by the user
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
gemini_client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None

# Initialize spaCy model
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    logger.warning("spaCy model 'en_core_web_sm' not found. Some AI features may not work.")
    nlp = None

def summarize_conversations(text: str, summary_length: str = "Brief") -> str:
    """
    Summarize conversation text using Google Gemini
    
    Args:
        text: The conversation text to summarize
        summary_length: "Brief", "Detailed", or "Comprehensive"
    
    Returns:
        Summarized text
    """
    if not gemini_client:
        return "Google Gemini API key not configured. Cannot generate summary."
    
    try:
        # Determine summary instruction based on length
        length_instructions = {
            "Brief": "Provide a brief 2-3 sentence summary",
            "Detailed": "Provide a detailed summary covering key topics and participants",
            "Comprehensive": "Provide a comprehensive summary with timeline, key events, and analysis"
        }
        
        instruction = length_instructions.get(summary_length, "Provide a brief summary")
        
        prompt = f"""Analyze the following forensic conversation data and {instruction.lower()}. 
        Focus on:
        - Key participants and their roles
        - Main topics discussed
        - Important dates, times, or events mentioned
        - Any suspicious or noteworthy activities
        - Communication patterns
        
        Conversation data:
        {text[:4000]}  # Limit text to avoid token limits
        
        Please provide the summary in a professional forensic analysis format."""
        
        response = gemini_client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        
        return response.text or "Error: No response generated"
        
    except Exception as e:
        logger.error(f"Error generating conversation summary: {e}")
        return f"Error generating summary: {str(e)}"

def extract_entities_from_text(text: str, entity_types: List[str] = None, confidence_threshold: float = 0.7) -> List[Dict[str, Any]]:
    """
    Extract named entities from text using spaCy and Google Gemini
    
    Args:
        text: Text to analyze
        entity_types: List of entity types to extract (PERSON, ORG, GPE, etc.)
        confidence_threshold: Minimum confidence score for entities
    
    Returns:
        List of extracted entities with metadata
    """
    entities = []
    
    if not text or not text.strip():
        return entities
    
    # Use spaCy for initial entity extraction
    if nlp:
        try:
            doc = nlp(text)
            
            for ent in doc.ents:
                if entity_types and ent.label_ not in entity_types:
                    continue
                
                # spaCy doesn't provide confidence scores by default, so we'll use a heuristic
                confidence = min(0.9, max(0.5, len(ent.text) / 20))  # Simple heuristic
                
                if confidence >= confidence_threshold:
                    entities.append({
                        'text': ent.text,
                        'label': ent.label_,
                        'start': ent.start_char,
                        'end': ent.end_char,
                        'confidence': confidence,
                        'description': spacy.explain(ent.label_) or ent.label_
                    })
        
        except Exception as e:
            logger.warning(f"spaCy entity extraction failed: {e}")
    
    # Use Google Gemini for enhanced entity extraction
    if gemini_client:
        try:
            gemini_entities = extract_entities_with_gemini(text, entity_types)
            
            # Merge with spaCy results, avoiding duplicates
            for ai_entity in gemini_entities:
                # Check for duplicates based on text and position
                is_duplicate = any(
                    abs(ai_entity['start'] - existing['start']) < 5 and 
                    ai_entity['text'].lower() == existing['text'].lower()
                    for existing in entities
                )
                
                if not is_duplicate and ai_entity['confidence'] >= confidence_threshold:
                    entities.append(ai_entity)
        
        except Exception as e:
            logger.warning(f"Google Gemini entity extraction failed: {e}")
    
    # Sort by confidence score
    entities.sort(key=lambda x: x['confidence'], reverse=True)
    
    return entities

def extract_entities_with_gemini(text: str, entity_types: List[str] = None) -> List[Dict[str, Any]]:
    """Extract entities using Google Gemini"""
    if not gemini_client:
        return []
    
    try:
        entity_types_str = ", ".join(entity_types) if entity_types else "PERSON, ORG, GPE, PHONE, EMAIL, DATE, MONEY, LOC"
        
        prompt = f"""Extract named entities from the following forensic text data. 
        Focus on these entity types: {entity_types_str}
        
        For each entity found, provide:
        - text: the exact text of the entity
        - label: the entity type
        - start: character position where entity starts
        - end: character position where entity ends  
        - confidence: confidence score between 0 and 1
        - context: surrounding text for context
        
        Text to analyze:
        {text[:3000]}
        
        Respond with JSON in this format:
        {{"entities": [{{"text": "John Doe", "label": "PERSON", "start": 10, "end": 18, "confidence": 0.95, "context": "...surrounding text..."}}]}}"""
        
        response = gemini_client.models.generate_content(
            model="gemini-2.5-pro",
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json"
            )
        )
        
        if response.text:
            result = json.loads(response.text)
            return result.get('entities', [])
        else:
            return []
        
    except Exception as e:
        logger.error(f"Google Gemini entity extraction error: {e}")
        return []

def analyze_sentiment_batch(texts: List[str]) -> Dict[str, Any]:
    """
    Analyze sentiment for a batch of texts
    
    Args:
        texts: List of text strings to analyze
    
    Returns:
        Dictionary with sentiment analysis results
    """
    if not gemini_client or not texts:
        return {'overall': 'neutral', 'individual': [], 'summary': {}}
    
    try:
        # Limit to first 100 texts to avoid token limits
        texts_sample = texts[:100]
        combined_text = "\n---\n".join(texts_sample)
        
        prompt = f"""Analyze the sentiment of the following forensic communication data.
        Provide analysis for:
        1. Overall sentiment across all messages
        2. Individual message sentiments (positive, negative, neutral)
        3. Emotional indicators and patterns
        4. Any concerning or suspicious emotional patterns
        
        Communication data:
        {combined_text[:4000]}
        
        Respond with JSON in this format:
        {{
            "overall": "positive/negative/neutral",
            "confidence": 0.85,
            "individual_sentiments": ["positive", "neutral", "negative"],
            "emotion_distribution": {{"positive": 30, "neutral": 50, "negative": 20}},
            "concerning_patterns": ["description of any concerning patterns"],
            "key_emotional_indicators": ["anger", "fear", "joy"]
        }}"""
        
        response = gemini_client.models.generate_content(
            model="gemini-2.5-pro",
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json"
            )
        )
        
        if response.text:
            return json.loads(response.text)
        else:
            return {'overall': 'neutral', 'individual': [], 'summary': {}}
        
    except Exception as e:
        logger.error(f"Sentiment analysis error: {e}")
        return {
            'overall': 'neutral',
            'error': str(e),
            'individual': [],
            'summary': {}
        }

def detect_anomalies(data: List[Any], detection_type: str, sensitivity: str = "Medium") -> List[Dict[str, Any]]:
    """
    Detect anomalies in forensic data using AI analysis
    
    Args:
        data: List of data objects to analyze
        detection_type: Type of anomaly detection to perform
        sensitivity: "Low", "Medium", or "High"
    
    Returns:
        List of detected anomalies
    """
    if not gemini_client or not data:
        return []
    
    try:
        # Convert data to analyzable format
        if detection_type == "Communication Patterns":
            analysis_data = analyze_communication_patterns(data)
        elif detection_type == "Temporal Anomalies":
            analysis_data = analyze_temporal_patterns(data)
        elif detection_type == "Content Anomalies":
            analysis_data = analyze_content_patterns(data)
        else:
            analysis_data = str(data[:50])  # Fallback for other types
        
        sensitivity_instructions = {
            "Low": "Only flag highly unusual patterns",
            "Medium": "Flag moderately suspicious patterns",
            "High": "Flag any potentially unusual patterns"
        }
        
        instruction = sensitivity_instructions.get(sensitivity, "Flag moderately suspicious patterns")
        
        prompt = f"""Analyze the following forensic data for anomalies and suspicious patterns.
        Detection type: {detection_type}
        Sensitivity: {sensitivity} - {instruction}
        
        Look for:
        - Unusual communication patterns
        - Suspicious timing or frequency
        - Abnormal content or behavior
        - Data inconsistencies
        - Potential evidence tampering
        
        Data to analyze:
        {analysis_data}
        
        Respond with JSON in this format:
        {{
            "anomalies": [
                {{
                    "type": "anomaly_type",
                    "severity": "High/Medium/Low", 
                    "confidence": 0.85,
                    "description": "detailed description",
                    "evidence": "supporting evidence",
                    "timestamp": "if applicable",
                    "recommendation": "suggested action"
                }}
            ]
        }}"""
        
        response = gemini_client.models.generate_content(
            model="gemini-2.5-pro",
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json"
            )
        )
        
        if response.text:
            result = json.loads(response.text)
            return result.get('anomalies', [])
        else:
            return []
        
    except Exception as e:
        logger.error(f"Anomaly detection error: {e}")
        return [{'type': 'Error', 'description': f"Analysis failed: {str(e)}"}]

def generate_investigation_report(report_data: Dict[str, Any], report_type: str, output_format: str = "Structured Text") -> str:
    """
    Generate comprehensive investigation report using AI
    
    Args:
        report_data: Dictionary containing case data and analysis results
        report_type: Type of report to generate
        output_format: Output format (Structured Text, JSON, Markdown)
    
    Returns:
        Generated report content
    """
    if not gemini_client:
        return "Google Gemini API key not configured. Cannot generate report."
    
    try:
        case_info = report_data.get('case_info', {})
        sections = report_data.get('sections', {})
        
        prompt = f"""Generate a professional forensic investigation report based on the provided data.
        
        Report Type: {report_type}
        Output Format: {output_format}
        
        Case Information:
        - Case Name: {case_info.get('name', 'Unknown')}
        - Investigator: {case_info.get('investigator', 'Unknown')}
        - Date Created: {case_info.get('created_at', 'Unknown')}
        - Description: {case_info.get('description', 'No description')}
        
        Analysis Sections:
        {json.dumps(sections, indent=2)}
        
        Generate a comprehensive {report_type.lower()} that includes:
        1. Executive Summary
        2. Case Overview
        3. Evidence Analysis
        4. Key Findings
        5. Timeline of Events
        6. Communication Analysis
        7. Digital Evidence Summary
        8. Conclusions and Recommendations
        9. Technical Appendix
        
        Ensure the report is professional, detailed, and suitable for legal proceedings.
        Format: {output_format}"""
        
        response = gemini_client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        
        return response.text or "Error: No response generated"
        
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        return f"Error generating report: {str(e)}"

def analyze_communication_patterns(messages: List[Any]) -> str:
    """Analyze communication patterns for anomaly detection"""
    try:
        if not messages:
            return "No messages to analyze"
        
        # Extract key metrics
        total_messages = len(messages)
        senders = set()
        time_patterns = []
        content_lengths = []
        
        for msg in messages:
            if hasattr(msg, 'sender') and msg.sender:
                senders.add(msg.sender)
            if hasattr(msg, 'timestamp') and msg.timestamp:
                time_patterns.append(msg.timestamp.hour)
            if hasattr(msg, 'content') and msg.content:
                content_lengths.append(len(msg.content))
        
        analysis = {
            'total_messages': total_messages,
            'unique_senders': len(senders),
            'average_content_length': sum(content_lengths) / len(content_lengths) if content_lengths else 0,
            'peak_hours': max(set(time_patterns), key=time_patterns.count) if time_patterns else 'Unknown',
            'message_frequency': total_messages / max(1, len(set(time_patterns)))
        }
        
        return json.dumps(analysis, indent=2)
        
    except Exception as e:
        logger.error(f"Communication pattern analysis error: {e}")
        return f"Analysis error: {str(e)}"

def analyze_temporal_patterns(data: List[Any]) -> str:
    """Analyze temporal patterns in the data"""
    try:
        timestamps = []
        for item in data:
            if hasattr(item, 'timestamp') and item.timestamp:
                timestamps.append(item.timestamp)
        
        if not timestamps:
            return "No temporal data available"
        
        # Sort timestamps
        timestamps.sort()
        
        # Calculate gaps between consecutive events
        gaps = []
        for i in range(1, len(timestamps)):
            gap = (timestamps[i] - timestamps[i-1]).total_seconds()
            gaps.append(gap)
        
        analysis = {
            'total_events': len(timestamps),
            'time_span_hours': (timestamps[-1] - timestamps[0]).total_seconds() / 3600 if len(timestamps) > 1 else 0,
            'average_gap_minutes': sum(gaps) / len(gaps) / 60 if gaps else 0,
            'max_gap_hours': max(gaps) / 3600 if gaps else 0,
            'min_gap_seconds': min(gaps) if gaps else 0
        }
        
        return json.dumps(analysis, indent=2)
        
    except Exception as e:
        logger.error(f"Temporal pattern analysis error: {e}")
        return f"Analysis error: {str(e)}"

def analyze_content_patterns(data: List[Any]) -> str:
    """Analyze content patterns in the data"""
    try:
        content_items = []
        for item in data:
            if hasattr(item, 'content') and item.content:
                content_items.append(item.content)
        
        if not content_items:
            return "No content data available"
        
        # Basic content analysis
        total_content = len(content_items)
        total_chars = sum(len(content) for content in content_items)
        avg_length = total_chars / total_content if total_content > 0 else 0
        
        # Count unique words (simplified)
        all_words = []
        for content in content_items:
            words = content.lower().split()
            all_words.extend(words)
        
        unique_words = len(set(all_words))
        word_frequency = {}
        for word in all_words:
            word_frequency[word] = word_frequency.get(word, 0) + 1
        
        # Most common words
        common_words = sorted(word_frequency.items(), key=lambda x: x[1], reverse=True)[:10]
        
        analysis = {
            'total_content_items': total_content,
            'average_content_length': avg_length,
            'total_words': len(all_words),
            'unique_words': unique_words,
            'vocabulary_diversity': unique_words / len(all_words) if all_words else 0,
            'most_common_words': common_words
        }
        
        return json.dumps(analysis, indent=2)
        
    except Exception as e:
        logger.error(f"Content pattern analysis error: {e}")
        return f"Analysis error: {str(e)}"

def extract_phone_numbers(text: str) -> List[str]:
    """Extract phone numbers from text using regex and NLP"""
    import re
    
    phone_patterns = [
        r'\b\d{3}-\d{3}-\d{4}\b',  # XXX-XXX-XXXX
        r'\b\(\d{3}\)\s*\d{3}-\d{4}\b',  # (XXX) XXX-XXXX
        r'\b\d{3}\.\d{3}\.\d{4}\b',  # XXX.XXX.XXXX
        r'\b\d{10}\b',  # XXXXXXXXXX
        r'\+\d{1,3}\s*\d{3,4}\s*\d{3,4}\s*\d{3,4}',  # International
    ]
    
    phone_numbers = []
    for pattern in phone_patterns:
        matches = re.findall(pattern, text)
        phone_numbers.extend(matches)
    
    return list(set(phone_numbers))  # Remove duplicates

def extract_email_addresses(text: str) -> List[str]:
    """Extract email addresses from text"""
    import re
    
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, text)
    
    return list(set(emails))  # Remove duplicates

def classify_message_urgency(content: str) -> Dict[str, Any]:
    """Classify message urgency and importance"""
    if not gemini_client or not content:
        return {'urgency': 'low', 'confidence': 0.5, 'reasoning': 'Unable to analyze'}
    
    try:
        prompt = f"""Analyze the urgency and importance of this forensic message content.
        Consider factors like:
        - Language indicating emergency or time sensitivity
        - Threatening or concerning content
        - Legal or criminal implications
        - Emotional intensity
        
        Message content:
        {content[:1000]}
        
        Respond with JSON:
        {{
            "urgency": "low/medium/high/critical",
            "confidence": 0.85,
            "reasoning": "explanation of classification",
            "key_indicators": ["specific words or phrases"],
            "recommended_priority": "immediate/high/normal/low"
        }}"""
        
        response = gemini_client.models.generate_content(
            model="gemini-2.5-pro",
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json"
            )
        )
        
        if response.text:
            return json.loads(response.text)
        else:
            return {'urgency': 'medium', 'confidence': 0.3, 'reasoning': 'No response from AI'}
        
    except Exception as e:
        logger.error(f"Message urgency classification error: {e}")
        return {
            'urgency': 'medium',
            'confidence': 0.3,
            'reasoning': f'Analysis failed: {str(e)}',
            'error': True
        }

def analyze_conversation_relationships(messages: List[Any]) -> Dict[str, Any]:
    """Analyze relationships between conversation participants"""
    if not messages:
        return {}
    
    try:
        participants = {}
        interactions = {}
        
        for msg in messages:
            if hasattr(msg, 'sender') and hasattr(msg, 'recipient'):
                sender = msg.sender
                recipient = msg.recipient
                
                if sender and recipient:
                    # Count interactions
                    pair = tuple(sorted([sender, recipient]))
                    interactions[pair] = interactions.get(pair, 0) + 1
                    
                    # Track individual participation
                    participants[sender] = participants.get(sender, 0) + 1
                    if recipient not in participants:
                        participants[recipient] = 0
        
        # Find most active participants
        most_active = sorted(participants.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Find strongest relationships
        strongest_relationships = sorted(interactions.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'total_participants': len(participants),
            'most_active_participants': most_active,
            'strongest_relationships': strongest_relationships,
            'total_interactions': sum(interactions.values()),
            'unique_pairs': len(interactions)
        }
        
    except Exception as e:
        logger.error(f"Relationship analysis error: {e}")
        return {'error': str(e)}

def generate_keyword_alerts(text: str, suspicious_keywords: List[str] = None) -> List[Dict[str, Any]]:
    """Generate alerts for suspicious keywords in text"""
    if not text:
        return []
    
    # Default suspicious keywords for forensic analysis
    if not suspicious_keywords:
        suspicious_keywords = [
            'delete', 'destroy', 'hide', 'secret', 'cover up', 'evidence',
            'drug', 'weapon', 'threat', 'kill', 'murder', 'bomb',
            'money laundering', 'illegal', 'stolen', 'fraud', 'scam'
        ]
    
    alerts = []
    text_lower = text.lower()
    
    for keyword in suspicious_keywords:
        if keyword.lower() in text_lower:
            # Find all occurrences
            import re
            pattern = re.compile(re.escape(keyword.lower()))
            matches = list(pattern.finditer(text_lower))
            
            for match in matches:
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end]
                
                alerts.append({
                    'keyword': keyword,
                    'position': match.start(),
                    'context': context,
                    'severity': classify_keyword_severity(keyword),
                    'timestamp': None  # Would be filled by caller
                })
    
    return alerts

def classify_keyword_severity(keyword: str) -> str:
    """Classify the severity level of a suspicious keyword"""
    high_severity = ['kill', 'murder', 'bomb', 'weapon', 'threat']
    medium_severity = ['drug', 'illegal', 'stolen', 'fraud', 'destroy evidence']
    
    keyword_lower = keyword.lower()
    
    if any(severe in keyword_lower for severe in high_severity):
        return 'high'
    elif any(medium in keyword_lower for medium in medium_severity):
        return 'medium'
    else:
        return 'low'
