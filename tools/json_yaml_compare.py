#!/usr/bin/env python3
"""
JSON to YAML Schema Validator and Converter

This script compares attributes in a JSON payload against a YAML schema file,
identifying missing attributes and type mismatches. It also suggests YAML entries
for missing attributes in the appropriate format.

Usage:
    python json_yaml_compare.py <json_file> <yaml_file>

Example:
    python json_yaml_compare.py fabric_flow_collection.json generator/defs/fabric.yaml
"""

import sys
import json
import yaml
import re
from collections import defaultdict
import os.path


def camel_to_snake(name):
    """
    Convert camelCase to snake_case.
    """
    name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()


def extract_json_attributes(data, parent_key='', flattened_keys=None, nested_paths=None):
    """
    Extract all attribute names from a JSON object, including nested ones.
    Returns both flattened keys and full nested paths for each attribute.
    """
    if flattened_keys is None:
        flattened_keys = set()
    if nested_paths is None:
        nested_paths = defaultdict(list)
    
    if isinstance(data, dict):
        for key, value in data.items():
            new_key = f"{parent_key}.{key}" if parent_key else key
            # Add the key itself
            flattened_keys.add(key)
            
            # Keep track of nested paths
            if parent_key:
                nested_paths[key].append(parent_key)
            
            # If we have a dict or list, recurse
            if isinstance(value, (dict, list)):
                extract_json_attributes(value, new_key, flattened_keys, nested_paths)
    
    elif isinstance(data, list):
        for i, item in enumerate(data):
            new_key = f"{parent_key}[{i}]" if parent_key else f"[{i}]"
            if isinstance(item, (dict, list)):
                extract_json_attributes(item, new_key, flattened_keys, nested_paths)
            # For list items, we don't add keys as they're indexed
    
    return flattened_keys, nested_paths


def extract_yaml_model_names(yaml_data):
    """
    Extract model names from the YAML schema file.
    Returns a dict mapping model_name to its attributes and a dict mapping tf_name to model_name.
    """
    yaml_models = {}
    tf_to_model = {}
    
    if isinstance(yaml_data, dict) and 'attributes' in yaml_data:
        for attr in yaml_data['attributes']:
            if 'model_name' in attr:
                yaml_models[attr['model_name']] = attr
                if 'tf_name' in attr:
                    tf_to_model[attr['tf_name']] = attr['model_name']
    
    return yaml_models, tf_to_model


def infer_yaml_type(json_value):
    """
    Infer YAML type based on JSON value.
    """
    if isinstance(json_value, bool):
        return "Bool", "bool"
    elif isinstance(json_value, int):
        return "Int64", None
    elif isinstance(json_value, float):
        return "Float64", None
    elif isinstance(json_value, str):
        try:
            int(json_value)
            return "String", None  # It's a string that could be parsed as int
        except ValueError:
            return "String", None
    elif isinstance(json_value, (list, dict)):
        return "Object", None
    return "String", None  # Default


def generate_yaml_entry(key, json_value, nested_path=None):
    """
    Generate a YAML entry for a missing attribute.
    """
    yaml_type, ndfc_type = infer_yaml_type(json_value)
    tf_name = camel_to_snake(key)
    
    entry = []
    entry.append("  - model_name: " + key)
    entry.append("    tf_name: " + tf_name)
    entry.append("    type: " + yaml_type)
    entry.append(f"    optional: true")
    entry.append(f"    computed: true")
    
    # Add example value
    if isinstance(json_value, (bool, int, float)):
        entry.append(f"    example: {str(json_value).lower()}")
    elif isinstance(json_value, str) and json_value:
        entry.append(f"    example: {json_value}")
    else:
        entry.append(f"    example: \"\"")
    
    # Add ndfc_type if applicable
    if ndfc_type:
        entry.append(f"    ndfc_type: {ndfc_type}")
    
    # Add nesting if available
    if nested_path:
        entry.append("    ndfc_nested:")
        for path in nested_path:
            entry.append(f"    - {path}")
    
    # Add a placeholder description
    entry.append(f"    description: {key} configuration parameter")
    
    return "\n".join(entry)


def find_matching_yaml_attribute(json_key, yaml_models, tf_to_model, debug=False):
    """
    Find if a JSON attribute has a matching entry in the YAML schema.
    """
    # Direct match
    if json_key in yaml_models:
        if debug:
            print(f"Direct match found for {json_key}")
        return yaml_models[json_key], None
    
    # Try snake_case version
    snake_key = camel_to_snake(json_key)
    if snake_key in tf_to_model:
        model_name = tf_to_model[snake_key]
        if debug:
            print(f"Snake case match found for {json_key} -> {snake_key} -> {model_name}")
        return yaml_models[model_name], None
    
    # Try case-insensitive match
    json_key_lower = json_key.lower()
    for yaml_key, yaml_attr in yaml_models.items():
        if yaml_key.lower() == json_key_lower:
            if debug:
                print(f"Case-insensitive match found for {json_key} -> {yaml_key}")
            return yaml_attr, None
        
        # Also try tf_name case-insensitive
        tf_name = yaml_attr.get('tf_name', '')
        if tf_name.lower() == json_key_lower or tf_name.lower() == snake_key.lower():
            if debug:
                print(f"Case-insensitive tf_name match found for {json_key} -> {tf_name}")
            return yaml_attr, None
    
    return None, f"No match found for {json_key}"


def check_type_compatibility(json_value, yaml_attr):
    """
    Check if the JSON value type is compatible with the YAML schema type.
    """
    yaml_type = yaml_attr.get('type')
    
    if yaml_type == 'Bool' and not isinstance(json_value, bool):
        return False, f"Type mismatch: {yaml_type} vs {type(json_value).__name__}"
    elif yaml_type == 'Int64' and not (isinstance(json_value, int) or 
                                        (isinstance(json_value, str) and json_value.isdigit())):
        return False, f"Type mismatch: {yaml_type} vs {type(json_value).__name__}"
    elif yaml_type == 'Float64' and not isinstance(json_value, (float, int)):
        return False, f"Type mismatch: {yaml_type} vs {type(json_value).__name__}"
    
    return True, None


def main():
    """
    Main function to compare JSON attributes against a YAML schema.
    """
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <json_file> <yaml_file>")
        sys.exit(1)
    
    json_file = sys.argv[1]
    yaml_file = sys.argv[2]
    
    # Check if files exist
    if not os.path.exists(json_file):
        print(f"Error: JSON file {json_file} not found")
        sys.exit(1)
    if not os.path.exists(yaml_file):
        print(f"Error: YAML file {yaml_file} not found")
        sys.exit(1)
    
    # Load JSON
    with open(json_file, 'r') as f:
        try:
            json_data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON file: {e}")
            sys.exit(1)
    
    # Load YAML
    with open(yaml_file, 'r') as f:
        try:
            yaml_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"Error parsing YAML file: {e}")
            sys.exit(1)
    
    # Extract attributes
    json_attributes, nested_paths = extract_json_attributes(json_data)
    
    # Specifically handle management section which has special nesting
    if 'management' in json_data:
        mgmt_attrs, mgmt_nested = extract_json_attributes(json_data['management'])
        for attr in mgmt_attrs:
            nested_paths[attr].append('management')
    
    yaml_models, tf_to_model = extract_yaml_model_names(yaml_data)
    
    # Compare attributes
    missing_attrs = []
    type_mismatches = []
    matched_attrs = []
    
    for attr in json_attributes:
        # Skip some top-level keys that aren't expected in the schema
        if attr in ('name', 'location', 'management'):
            continue
            
        yaml_attr, error = find_matching_yaml_attribute(attr, yaml_models, tf_to_model)
        
        if not yaml_attr:
            # Extract the value to suggest type
            value = get_value_from_json(json_data, attr, nested_paths)
            missing_attrs.append((attr, value, nested_paths.get(attr, [])))
            continue
        
        # Found a match
        matched_attrs.append((attr, yaml_attr['model_name'], yaml_attr.get('tf_name', '')))
        
        # Check type compatibility if we found a match
        value = get_value_from_json(json_data, attr, nested_paths)
        if value is not None:  # Skip null values
            compatible, error = check_type_compatibility(value, yaml_attr)
            if not compatible:
                type_mismatches.append((attr, yaml_attr['type'], type(value).__name__, error))
    
    # Handle special case for management section
    if 'management' in json_data:
        for attr, value in json_data['management'].items():
            # Skip netflowSettings as we'll handle it separately
            if attr == 'netflowSettings':
                continue
                
            yaml_attr, error = find_matching_yaml_attribute(attr, yaml_models, tf_to_model)
            
            if yaml_attr:
                matched_attrs.append((attr, yaml_attr['model_name'], yaml_attr.get('tf_name', '')))
                # Check type compatibility
                if value is not None:
                    compatible, error = check_type_compatibility(value, yaml_attr)
                    if not compatible:
                        type_mismatches.append((attr, yaml_attr['type'], type(value).__name__, error))
            else:
                missing_attrs.append((attr, value, ['management']))
    
    # Handle special case for netflowSettings
    netflow_settings_attrs = []
    if 'management' in json_data and 'netflowSettings' in json_data['management']:
        netflow_settings = json_data['management']['netflowSettings']
        # Extract netflow attributes
        for key, value in netflow_settings.items():
            yaml_attr, error = find_matching_yaml_attribute(key, yaml_models, tf_to_model)
            
            if yaml_attr:
                matched_attrs.append((key, yaml_attr['model_name'], yaml_attr.get('tf_name', '')))
                if value is not None:
                    compatible, error = check_type_compatibility(value, yaml_attr)
                    if not compatible:
                        type_mismatches.append((key, yaml_attr['type'], type(value).__name__, error))
            else:
                netflow_settings_attrs.append((key, value))
    
    # Print results
    print(f"\nAnalysis results for {json_file} vs {yaml_file}:\n")
    
    print(f"Found {len(matched_attrs)} matched attributes:")
    for i, (json_attr, yaml_model, tf_name) in enumerate(sorted(matched_attrs, key=lambda x: x[0]), 1):
        print(f"{i}. JSON: {json_attr} -> YAML: {yaml_model} (tf_name: {tf_name})")
    
    print(f"\nFound {len(missing_attrs)} missing attributes:")
    for i, (attr, value, paths) in enumerate(missing_attrs, 1):
        print(f"\n{i}. Missing attribute: {attr}")
        print(f"   Value: {value}")
        print(f"   Nested paths: {paths}")
        print("\n   Suggested YAML entry:")
        print(generate_yaml_entry(attr, value, paths))
    
    # Specifically highlight netflow settings which need special handling
    if netflow_settings_attrs:
        print(f"\nNetflow Settings (requires special handling):")
        for i, (attr, value) in enumerate(netflow_settings_attrs, 1):
            print(f"\n{i}. Netflow attribute: {attr}")
            print(f"   Value: {value}")
            print("\n   These need to be structured appropriately in the schema")
    
    print(f"\nFound {len(type_mismatches)} type mismatches:")
    for i, (attr, yaml_type, json_type, error) in enumerate(type_mismatches, 1):
        print(f"{i}. {attr}: {error} (YAML: {yaml_type}, JSON: {json_type})")


def get_value_from_json(json_data, attr, nested_paths):
    """
    Extract a value from the JSON data based on attribute name and possible paths.
    """
    # First try direct access
    if attr in json_data:
        return json_data[attr]
    
    # Try nested paths
    paths = nested_paths.get(attr, [])
    for path in paths:
        if path == 'management' and 'management' in json_data and attr in json_data['management']:
            return json_data['management'][attr]
        elif path == 'netflowSettings' and 'management' in json_data and 'netflowSettings' in json_data['management']:
            netflow = json_data['management']['netflowSettings']
            if attr in netflow:
                return netflow[attr]
    
    return None


if __name__ == "__main__":
    main()
