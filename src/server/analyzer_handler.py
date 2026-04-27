"""
analyzer_handler.py is a file managing interactions between the server and the analyzer.py functionalities
"""

# Imports - Default Libraries
import json

# Imports - Internal Modules
from server.user_db import DatabaseError


# External Methods
def handle_get_url_analysis(db, data, success_builder, error_builder):
    """Retrieve cached URL analysis from database; returns not_found if cache miss"""
    url = data.get('url')
    if not url:
        return error_builder('Missing url field')

    result = db.get_url_analysis(url)
    if result is None:
        return success_builder({'found': False})

    # Deserialize analysis_data JSON string back to dict
    if isinstance(result.get('analysis_data'), str):
        try:
            result['analysis_data'] = json.loads(result['analysis_data'])
        except (json.JSONDecodeError, TypeError):
            pass

    return success_builder({'found': True, 'analysis': result})


def handle_cache_url_analysis(db, data, success_builder, error_builder):
    """Persist a locally-computed URL analysis result to the database"""
    required = ('url', 'rating', 'recommendation', 'is_shortened', 'analysis_data')
    for field in required:
        if field not in data:
            return error_builder(f'Missing field: {field}')

    analysis_data_raw = data['analysis_data']
    if isinstance(analysis_data_raw, dict):
        analysis_data_raw = json.dumps(analysis_data_raw)

    try:
        db.create_url_analysis(
            url=data['url'],
            rating=data['rating'],
            recommendation=data['recommendation'],
            is_shortened=data['is_shortened'],
            expanded_url=data.get('expanded_url'),
            analysis_data=analysis_data_raw,
        )
        return success_builder()
    except DatabaseError:
        return error_builder('Failed to cache URL analysis')
