import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import networkx as nx
from pyvis.network import Network
import tempfile
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
from utils.db import get_db_session, ChatMessage, Call, Contact, Media, Location
from sqlalchemy import func

logger = logging.getLogger(__name__)

def create_timeline_chart(case_id: int, timeline_type: str = "All Communications", 
                         granularity: str = "Day", start_date=None, end_date=None):
    """
    Create timeline visualization for communications
    
    Args:
        case_id: Case ID to analyze
        timeline_type: Type of timeline to create
        granularity: Time granularity (Hour, Day, Week, Month)
        start_date: Start date filter
        end_date: End date filter
    
    Returns:
        Plotly figure or None if no data
    """
    try:
        session = get_db_session()
        
        # Prepare data based on timeline type
        timeline_data = []
        
        if timeline_type in ["All Communications", "Messages Only"]:
            messages = session.query(ChatMessage).filter(ChatMessage.case_id == case_id)
            
            if start_date:
                messages = messages.filter(ChatMessage.timestamp >= start_date)
            if end_date:
                messages = messages.filter(ChatMessage.timestamp <= end_date)
            
            for msg in messages.all():
                if msg.timestamp:
                    timeline_data.append({
                        'timestamp': msg.timestamp,
                        'type': 'Message',
                        'sender': msg.sender or 'Unknown',
                        'app': msg.app_name or 'Unknown',
                        'content_preview': (msg.content[:50] + '...') if msg.content and len(msg.content) > 50 else msg.content
                    })
        
        if timeline_type in ["All Communications", "Calls Only"]:
            calls = session.query(Call).filter(Call.case_id == case_id)
            
            if start_date:
                calls = calls.filter(Call.timestamp >= start_date)
            if end_date:
                calls = calls.filter(Call.timestamp <= end_date)
            
            for call in calls.all():
                if call.timestamp:
                    timeline_data.append({
                        'timestamp': call.timestamp,
                        'type': 'Call',
                        'sender': call.phone_number or 'Unknown',
                        'app': f"{call.call_type} Call" if call.call_type else 'Call',
                        'content_preview': f"{call.direction} - {call.duration}s" if call.duration else call.direction
                    })
        
        if timeline_type in ["All Communications", "Media Only"]:
            media = session.query(Media).filter(Media.case_id == case_id)
            
            if start_date:
                media = media.filter(Media.timestamp >= start_date)
            if end_date:
                media = media.filter(Media.timestamp <= end_date)
            
            for item in media.all():
                if item.timestamp:
                    timeline_data.append({
                        'timestamp': item.timestamp,
                        'type': 'Media',
                        'sender': item.file_name or 'Unknown',
                        'app': item.file_type or 'Media',
                        'content_preview': f"File: {item.file_name}"
                    })
        
        session.close()
        
        if not timeline_data:
            return None
        
        # Convert to DataFrame
        df = pd.DataFrame(timeline_data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Group by time granularity
        if granularity == "Hour":
            df['time_group'] = df['timestamp'].dt.floor('H')
        elif granularity == "Day":
            df['time_group'] = df['timestamp'].dt.date
        elif granularity == "Week":
            df['time_group'] = df['timestamp'].dt.to_period('W').dt.start_time
        elif granularity == "Month":
            df['time_group'] = df['timestamp'].dt.to_period('M').dt.start_time
        
        # Aggregate data
        agg_data = df.groupby(['time_group', 'type']).size().reset_index(name='count')
        
        # Create timeline chart
        fig = px.line(
            agg_data, 
            x='time_group', 
            y='count', 
            color='type',
            title=f'{timeline_type} Timeline ({granularity})',
            labels={'count': 'Number of Events', 'time_group': 'Time'}
        )
        
        fig.update_layout(
            xaxis_title='Time',
            yaxis_title='Number of Events',
            hovermode='x unified'
        )
        
        return fig
        
    except Exception as e:
        logger.error(f"Error creating timeline chart: {e}")
        return None

def create_contact_network(case_id: int, network_type: str = "Communication Network", 
                          min_interactions: int = 5):
    """
    Create interactive contact network graph
    
    Args:
        case_id: Case ID to analyze
        network_type: Type of network to create
        min_interactions: Minimum interactions to include a contact
    
    Returns:
        HTML string for interactive network or None
    """
    try:
        session = get_db_session()
        
        # Build network data
        edges = []
        nodes = set()
        
        if network_type == "Communication Network":
            # Get message interactions
            messages = session.query(ChatMessage).filter(
                ChatMessage.case_id == case_id,
                ChatMessage.sender.isnot(None),
                ChatMessage.recipient.isnot(None)
            ).all()
            
            interaction_counts = {}
            for msg in messages:
                sender = msg.sender
                recipient = msg.recipient
                
                if sender and recipient and sender != recipient:
                    pair = tuple(sorted([sender, recipient]))
                    interaction_counts[pair] = interaction_counts.get(pair, 0) + 1
                    nodes.add(sender)
                    nodes.add(recipient)
            
            # Filter by minimum interactions and create edges
            for (node1, node2), count in interaction_counts.items():
                if count >= min_interactions:
                    edges.append({
                        'from': node1,
                        'to': node2,
                        'weight': count,
                        'title': f'{count} messages'
                    })
        
        elif network_type == "Call Patterns":
            # Get call interactions
            calls = session.query(Call).filter(
                Call.case_id == case_id,
                Call.phone_number.isnot(None)
            ).all()
            
            call_counts = {}
            for call in calls:
                phone = call.phone_number
                contact = call.contact_name or phone
                
                if phone and contact:
                    nodes.add(contact)
                    # For calls, we might not have recipient info, so create hub-style network
                    call_counts[contact] = call_counts.get(contact, 0) + 1
            
            # Create hub network centered on most active contacts
            for contact, count in call_counts.items():
                if count >= min_interactions:
                    edges.append({
                        'from': 'Call Hub',
                        'to': contact,
                        'weight': count,
                        'title': f'{count} calls'
                    })
                    nodes.add('Call Hub')
        
        session.close()
        
        if not edges:
            return None
        
        # Create NetworkX graph
        G = nx.Graph()
        
        # Add nodes
        for node in nodes:
            G.add_node(node)
        
        # Add edges
        for edge in edges:
            G.add_edge(edge['from'], edge['to'], weight=edge['weight'], title=edge['title'])
        
        # Create PyVis network
        net = Network(height="600px", width="100%", bgcolor="#ffffff", font_color="black")
        
        # Add nodes with sizing based on degree
        for node in G.nodes():
            degree = G.degree(node)
            size = min(50, max(10, degree * 5))  # Scale node size
            net.add_node(node, label=node, size=size, title=f"Connections: {degree}")
        
        # Add edges with thickness based on weight
        for edge in edges:
            weight = edge['weight']
            width = min(10, max(1, weight / 5))  # Scale edge width
            net.add_edge(
                edge['from'], 
                edge['to'], 
                width=width, 
                title=edge['title'],
                color={'color': '#848484', 'highlight': '#ff0000'}
            )
        
        # Configure physics
        net.set_options("""
        var options = {
          "physics": {
            "enabled": true,
            "stabilization": {"iterations": 100}
          },
          "interaction": {
            "hover": true,
            "selectConnectedEdges": true
          }
        }
        """)
        
        # Generate HTML
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            net.save_graph(f.name)
            with open(f.name, 'r') as html_file:
                html_content = html_file.read()
            os.unlink(f.name)
        
        return html_content
        
    except Exception as e:
        logger.error(f"Error creating contact network: {e}")
        return None

def create_communication_heatmap(case_id: int):
    """
    Create communication activity heatmap
    
    Args:
        case_id: Case ID to analyze
    
    Returns:
        Plotly figure or None
    """
    try:
        session = get_db_session()
        
        # Get messages with timestamps
        messages = session.query(ChatMessage).filter(
            ChatMessage.case_id == case_id,
            ChatMessage.timestamp.isnot(None)
        ).all()
        
        session.close()
        
        if not messages:
            return None
        
        # Create hourly activity matrix
        activity_data = []
        for msg in messages:
            activity_data.append({
                'day_of_week': msg.timestamp.strftime('%A'),
                'hour': msg.timestamp.hour,
                'timestamp': msg.timestamp
            })
        
        df = pd.DataFrame(activity_data)
        
        # Create heatmap data
        heatmap_data = df.groupby(['day_of_week', 'hour']).size().reset_index(name='count')
        
        # Pivot for heatmap
        heatmap_pivot = heatmap_data.pivot(index='day_of_week', columns='hour', values='count').fillna(0)
        
        # Reorder days
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        heatmap_pivot = heatmap_pivot.reindex(day_order)
        
        # Create heatmap
        fig = go.Figure(data=go.Heatmap(
            z=heatmap_pivot.values,
            x=list(range(24)),  # Hours 0-23
            y=day_order,
            colorscale='Blues',
            showscale=True,
            hoverongaps=False,
            hovertemplate='Day: %{y}<br>Hour: %{x}:00<br>Messages: %{z}<extra></extra>'
        ))
        
        fig.update_layout(
            title='Communication Activity Heatmap',
            xaxis_title='Hour of Day',
            yaxis_title='Day of Week',
            xaxis=dict(tickmode='linear', tick0=0, dtick=2),
        )
        
        return fig
        
    except Exception as e:
        logger.error(f"Error creating communication heatmap: {e}")
        return None

def create_location_map(case_id: int, source_filter: str = "All Sources", 
                       time_filter: str = "All Time"):
    """
    Create location map visualization
    
    Args:
        case_id: Case ID to analyze
        source_filter: Filter by location source
        time_filter: Filter by time period
    
    Returns:
        Plotly figure or None
    """
    try:
        session = get_db_session()
        
        # Query location data
        locations = session.query(Location).filter(
            Location.case_id == case_id,
            Location.latitude.isnot(None),
            Location.longitude.isnot(None)
        )
        
        # Apply source filter
        if source_filter != "All Sources":
            source_map = {
                "GPS Data": "GPS",
                "Cell Tower": "CELL_TOWER", 
                "WiFi": "WIFI",
                "Media EXIF": "EXIF"
            }
            if source_filter in source_map:
                locations = locations.filter(Location.source == source_map[source_filter])
        
        # Apply time filter
        if time_filter == "Last 24 Hours":
            cutoff = datetime.now() - timedelta(hours=24)
            locations = locations.filter(Location.timestamp >= cutoff)
        elif time_filter == "Last Week":
            cutoff = datetime.now() - timedelta(weeks=1)
            locations = locations.filter(Location.timestamp >= cutoff)
        elif time_filter == "Last Month":
            cutoff = datetime.now() - timedelta(days=30)
            locations = locations.filter(Location.timestamp >= cutoff)
        
        locations = locations.all()
        session.close()
        
        if not locations:
            return None
        
        # Prepare map data
        map_data = []
        for loc in locations:
            map_data.append({
                'lat': loc.latitude,
                'lon': loc.longitude,
                'timestamp': loc.timestamp.strftime('%Y-%m-%d %H:%M:%S') if loc.timestamp else 'Unknown',
                'source': loc.source or 'Unknown',
                'accuracy': loc.accuracy or 'Unknown',
                'activity': loc.activity or 'Unknown'
            })
        
        df = pd.DataFrame(map_data)
        
        # Create scatter mapbox
        fig = px.scatter_mapbox(
            df,
            lat='lat',
            lon='lon',
            color='source',
            size_max=15,
            zoom=10,
            hover_data=['timestamp', 'accuracy', 'activity'],
            title='Location Data Visualization'
        )
        
        # Update layout
        fig.update_layout(
            mapbox_style="open-street-map",
            height=600,
            margin={"r":0,"t":40,"l":0,"b":0}
        )
        
        return fig
        
    except Exception as e:
        logger.error(f"Error creating location map: {e}")
        return None

def create_activity_chart(case_id: int, activity_type: str = "App Usage", 
                         period: str = "Daily"):
    """
    Create activity pattern analysis chart
    
    Args:
        case_id: Case ID to analyze
        activity_type: Type of activity to analyze
        period: Analysis period (Daily, Weekly, Monthly)
    
    Returns:
        Plotly figure or None
    """
    try:
        session = get_db_session()
        
        activity_data = []
        
        if activity_type == "App Usage":
            # Analyze app usage from messages
            messages = session.query(ChatMessage).filter(
                ChatMessage.case_id == case_id,
                ChatMessage.app_name.isnot(None),
                ChatMessage.timestamp.isnot(None)
            ).all()
            
            for msg in messages:
                activity_data.append({
                    'timestamp': msg.timestamp,
                    'category': msg.app_name,
                    'type': 'Message'
                })
        
        elif activity_type == "Communication Patterns":
            # Analyze communication frequency
            messages = session.query(ChatMessage).filter(
                ChatMessage.case_id == case_id,
                ChatMessage.timestamp.isnot(None)
            ).all()
            
            calls = session.query(Call).filter(
                Call.case_id == case_id,
                Call.timestamp.isnot(None)
            ).all()
            
            for msg in messages:
                activity_data.append({
                    'timestamp': msg.timestamp,
                    'category': 'Messages',
                    'type': 'Communication'
                })
            
            for call in calls:
                activity_data.append({
                    'timestamp': call.timestamp,
                    'category': 'Calls',
                    'type': 'Communication'
                })
        
        elif activity_type == "Device Events":
            # Analyze various device events
            media = session.query(Media).filter(
                Media.case_id == case_id,
                Media.timestamp.isnot(None)
            ).all()
            
            for item in media:
                activity_data.append({
                    'timestamp': item.timestamp,
                    'category': item.file_type or 'Media',
                    'type': 'Device Event'
                })
        
        session.close()
        
        if not activity_data:
            return None
        
        # Convert to DataFrame
        df = pd.DataFrame(activity_data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Group by period
        if period == "Daily":
            df['period'] = df['timestamp'].dt.date
        elif period == "Weekly":
            df['period'] = df['timestamp'].dt.to_period('W').dt.start_time
        elif period == "Monthly":
            df['period'] = df['timestamp'].dt.to_period('M').dt.start_time
        
        # Aggregate data
        agg_data = df.groupby(['period', 'category']).size().reset_index(name='count')
        
        # Create stacked bar chart
        fig = px.bar(
            agg_data,
            x='period',
            y='count',
            color='category',
            title=f'{activity_type} Analysis ({period})',
            labels={'count': 'Number of Events', 'period': 'Time Period'}
        )
        
        fig.update_layout(
            xaxis_title='Time Period',
            yaxis_title='Number of Events',
            barmode='stack'
        )
        
        return fig
        
    except Exception as e:
        logger.error(f"Error creating activity chart: {e}")
        return None

def get_case_statistics(case_id: int) -> Dict[str, Any]:
    """
    Get comprehensive case statistics for overview
    
    Args:
        case_id: Case ID to analyze
    
    Returns:
        Dictionary with case statistics
    """
    try:
        session = get_db_session()
        
        stats = {}
        
        # Basic counts
        stats['total_messages'] = session.query(ChatMessage).filter(ChatMessage.case_id == case_id).count()
        stats['total_calls'] = session.query(Call).filter(Call.case_id == case_id).count()
        stats['unique_contacts'] = session.query(Contact).filter(Contact.case_id == case_id).count()
        stats['total_media'] = session.query(Media).filter(Media.case_id == case_id).count()
        
        # Communication breakdown
        communication_breakdown = {}
        
        # Messages by app
        message_apps = session.query(
            ChatMessage.app_name,
            func.count(ChatMessage.id)
        ).filter(ChatMessage.case_id == case_id).group_by(ChatMessage.app_name).all()
        
        for app, count in message_apps:
            app_name = app or 'Unknown App'
            communication_breakdown[f"Messages ({app_name})"] = count
        
        # Calls by type
        call_types = session.query(
            Call.call_type,
            func.count(Call.id)
        ).filter(Call.case_id == case_id).group_by(Call.call_type).all()
        
        for call_type, count in call_types:
            type_name = call_type or 'Unknown Type'
            communication_breakdown[f"Calls ({type_name})"] = count
        
        stats['communication_breakdown'] = communication_breakdown
        
        # Daily activity (last 30 days)
        thirty_days_ago = datetime.now() - timedelta(days=30)
        
        daily_messages = session.query(
            func.date(ChatMessage.timestamp).label('date'),
            func.count(ChatMessage.id).label('count')
        ).filter(
            ChatMessage.case_id == case_id,
            ChatMessage.timestamp >= thirty_days_ago
        ).group_by(func.date(ChatMessage.timestamp)).all()
        
        daily_activity = {}
        for date, count in daily_messages:
            daily_activity[str(date)] = count
        
        stats['daily_activity'] = daily_activity
        
        # Top contacts (by message count)
        top_contacts = session.query(
            ChatMessage.sender,
            func.count(ChatMessage.id).label('message_count')
        ).filter(
            ChatMessage.case_id == case_id,
            ChatMessage.sender.isnot(None)
        ).group_by(ChatMessage.sender).order_by(func.count(ChatMessage.id).desc()).limit(10).all()
        
        stats['top_contacts'] = [
            {'contact': contact, 'message_count': count}
            for contact, count in top_contacts
        ]
        
        session.close()
        return stats
        
    except Exception as e:
        logger.error(f"Error getting case statistics: {e}")
        return {}

def create_sentiment_timeline(case_id: int, sentiment_data: List[Dict]) -> go.Figure:
    """
    Create sentiment analysis timeline
    
    Args:
        case_id: Case ID
        sentiment_data: List of sentiment analysis results
    
    Returns:
        Plotly figure
    """
    try:
        if not sentiment_data:
            return None
        
        df = pd.DataFrame(sentiment_data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Map sentiment to numeric values
        sentiment_map = {'positive': 1, 'neutral': 0, 'negative': -1}
        df['sentiment_score'] = df['sentiment'].map(sentiment_map)
        
        # Create rolling average
        df = df.sort_values('timestamp')
        df['rolling_sentiment'] = df['sentiment_score'].rolling(window=10, center=True).mean()
        
        fig = go.Figure()
        
        # Add scatter points for individual sentiments
        colors = {'positive': 'green', 'neutral': 'gray', 'negative': 'red'}
        for sentiment in ['positive', 'neutral', 'negative']:
            sentiment_df = df[df['sentiment'] == sentiment]
            fig.add_trace(go.Scatter(
                x=sentiment_df['timestamp'],
                y=sentiment_df['sentiment_score'],
                mode='markers',
                name=sentiment.title(),
                marker=dict(color=colors[sentiment], size=8),
                hovertemplate=f'%{{x}}<br>Sentiment: {sentiment}<br>Confidence: %{{customdata}}<extra></extra>',
                customdata=sentiment_df['confidence'] if 'confidence' in sentiment_df.columns else None
            ))
        
        # Add rolling average line
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['rolling_sentiment'],
            mode='lines',
            name='Sentiment Trend',
            line=dict(color='blue', width=3),
            hovertemplate='%{x}<br>Average Sentiment: %{y:.2f}<extra></extra>'
        ))
        
        fig.update_layout(
            title='Sentiment Analysis Timeline',
            xaxis_title='Time',
            yaxis_title='Sentiment Score',
            yaxis=dict(range=[-1.2, 1.2], tickvals=[-1, 0, 1], ticktext=['Negative', 'Neutral', 'Positive']),
            hovermode='x unified'
        )
        
        return fig
        
    except Exception as e:
        logger.error(f"Error creating sentiment timeline: {e}")
        return None

def create_contact_frequency_chart(case_id: int) -> go.Figure:
    """
    Create contact frequency analysis chart
    
    Args:
        case_id: Case ID to analyze
    
    Returns:
        Plotly figure or None
    """
    try:
        session = get_db_session()
        
        # Get message frequency by contact
        contact_messages = session.query(
            ChatMessage.sender,
            func.count(ChatMessage.id).label('message_count')
        ).filter(
            ChatMessage.case_id == case_id,
            ChatMessage.sender.isnot(None)
        ).group_by(ChatMessage.sender).all()
        
        # Get call frequency by contact
        contact_calls = session.query(
            Call.phone_number,
            func.count(Call.id).label('call_count')
        ).filter(
            Call.case_id == case_id,
            Call.phone_number.isnot(None)
        ).group_by(Call.phone_number).all()
        
        session.close()
        
        # Combine data
        contact_data = {}
        
        for contact, count in contact_messages:
            contact_data[contact] = contact_data.get(contact, {})
            contact_data[contact]['messages'] = count
        
        for contact, count in contact_calls:
            contact_data[contact] = contact_data.get(contact, {})
            contact_data[contact]['calls'] = count
        
        if not contact_data:
            return None
        
        # Prepare data for plotting
        contacts = list(contact_data.keys())[:20]  # Top 20 contacts
        message_counts = [contact_data[c].get('messages', 0) for c in contacts]
        call_counts = [contact_data[c].get('calls', 0) for c in contacts]
        
        fig = go.Figure()
        
        fig.add_trace(go.Bar(
            name='Messages',
            x=contacts,
            y=message_counts,
            marker_color='lightblue'
        ))
        
        fig.add_trace(go.Bar(
            name='Calls',
            x=contacts,
            y=call_counts,
            marker_color='orange'
        ))
        
        fig.update_layout(
            title='Contact Communication Frequency',
            xaxis_title='Contact',
            yaxis_title='Number of Communications',
            barmode='group',
            xaxis_tickangle=-45
        )
        
        return fig
        
    except Exception as e:
        logger.error(f"Error creating contact frequency chart: {e}")
        return None

def export_visualization_data(case_id: int, viz_type: str) -> pd.DataFrame:
    """
    Export visualization data as DataFrame for further analysis
    
    Args:
        case_id: Case ID
        viz_type: Type of visualization data to export
    
    Returns:
        Pandas DataFrame with visualization data
    """
    try:
        session = get_db_session()
        
        if viz_type == "timeline":
            # Export timeline data
            messages = session.query(ChatMessage).filter(ChatMessage.case_id == case_id).all()
            calls = session.query(Call).filter(Call.case_id == case_id).all()
            
            data = []
            for msg in messages:
                data.append({
                    'timestamp': msg.timestamp,
                    'type': 'Message',
                    'source': msg.app_name,
                    'sender': msg.sender,
                    'content': msg.content
                })
            
            for call in calls:
                data.append({
                    'timestamp': call.timestamp,
                    'type': 'Call',
                    'source': call.call_type,
                    'sender': call.phone_number,
                    'content': f"Duration: {call.duration}s" if call.duration else "No duration"
                })
            
            return pd.DataFrame(data)
        
        elif viz_type == "network":
            # Export network data
            messages = session.query(ChatMessage).filter(
                ChatMessage.case_id == case_id,
                ChatMessage.sender.isnot(None),
                ChatMessage.recipient.isnot(None)
            ).all()
            
            edges = []
            for msg in messages:
                edges.append({
                    'source': msg.sender,
                    'target': msg.recipient,
                    'timestamp': msg.timestamp,
                    'app': msg.app_name
                })
            
            return pd.DataFrame(edges)
        
        elif viz_type == "locations":
            # Export location data
            locations = session.query(Location).filter(Location.case_id == case_id).all()
            
            data = []
            for loc in locations:
                data.append({
                    'timestamp': loc.timestamp,
                    'latitude': loc.latitude,
                    'longitude': loc.longitude,
                    'accuracy': loc.accuracy,
                    'source': loc.source,
                    'activity': loc.activity
                })
            
            return pd.DataFrame(data)
        
        session.close()
        return pd.DataFrame()
        
    except Exception as e:
        logger.error(f"Error exporting visualization data: {e}")
        return pd.DataFrame()
