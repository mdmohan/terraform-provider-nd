#!/usr/bin/env python3
"""
Simple script to extract and print JSON attributes and YAML schema attributes
"""

import json
import yaml
import sys
import os
import re


def camel_to_snake(name):
    """Convert camelCase to snake_case"""
    # Insert underscore between lowercase and uppercase letters
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def extract_json_attributes(json_obj, prefix="", result=None, paths=None):
    """
    Extract all attributes from JSON object, including nested ones.
    Returns a set of all attributes and dict mapping attributes to their path.
    """
    if result is None:
        result = set()
    if paths is None:
        paths = {}
    
    if isinstance(json_obj, dict):
        for key, value in json_obj.items():
            # Add the current key
            full_key = f"{prefix}.{key}" if prefix else key
            result.add(key)
            
            # Track paths
            if key not in paths:
                paths[key] = []
            if prefix and prefix not in paths[key]:
                paths[key].append(prefix)
            
            # Recurse for nested objects
            if isinstance(value, (dict, list)):
                extract_json_attributes(value, prefix=key, result=result, paths=paths)
    
    elif isinstance(json_obj, list):
        for item in json_obj:
            if isinstance(item, (dict, list)):
                extract_json_attributes(item, prefix=prefix, result=result, paths=paths)
    
    return result, paths


def extract_yaml_attributes(yaml_data):
    """
    Extract model_name and tf_name from YAML schema.
    Returns a dict mapping model_name to its attribute definition,
    and a dict mapping tf_name to model_name.
    """
    yaml_models = {}
    tf_to_model = {}
    
    # Debug: print the top-level keys in yaml_data
    print("\n=== YAML Debug ===")
    print(f"Top-level keys in YAML: {list(yaml_data.keys() if isinstance(yaml_data, dict) else [])}")
    
    # Handle the actual structure we find in fabric.yaml
    if isinstance(yaml_data, dict):
        # Check if this is a resource definition with attributes directly
        if 'attributes' in yaml_data and isinstance(yaml_data['attributes'], list):
            for attr in yaml_data['attributes']:
                if isinstance(attr, dict) and 'model_name' in attr:
                    model_name = attr['model_name']
                    yaml_models[model_name] = attr
                    if 'tf_name' in attr:
                        tf_name = attr['tf_name']
                        tf_to_model[tf_name] = model_name
        
        # If not found at top level, check 'resource' if it exists
        elif 'resource' in yaml_data and isinstance(yaml_data['resource'], dict):
            resource = yaml_data['resource']
            if 'attributes' in resource and isinstance(resource['attributes'], list):
                for attr in resource['attributes']:
                    if isinstance(attr, dict) and 'model_name' in attr:
                        model_name = attr['model_name']
                        yaml_models[model_name] = attr
                        if 'tf_name' in attr:
                            tf_name = attr['tf_name']
                            tf_to_model[tf_name] = model_name
    
    print(f"Found {len(yaml_models)} model_names and {len(tf_to_model)} tf_names")
    return yaml_models, tf_to_model


def is_attribute_in_yaml(json_key, yaml_models, tf_to_model):
    """
    Check if a JSON attribute exists in the YAML schema.
    Returns (True, match_type) if found, (False, None) if not found.
    match_type can be 'model_name', 'tf_name', or 'case_insensitive'.
    """
    # Direct match on model_name
    if json_key in yaml_models:
        return True, 'model_name'
    
    # Check for snake_case version in tf_names
    snake_key = camel_to_snake(json_key)
    if snake_key in tf_to_model:
        return True, 'tf_name'
    
    # Case-insensitive check on model_name
    json_key_lower = json_key.lower()
    for model_name in yaml_models.keys():
        if model_name.lower() == json_key_lower:
            return True, 'case_insensitive_model'
    
    # Case-insensitive check on tf_name
    for tf_name in tf_to_model.keys():
        if tf_name.lower() == snake_key.lower():
            return True, 'case_insensitive_tf'
    
    return False, None


def main():
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
            print(f"Loaded YAML file: {yaml_file}")
            if yaml_data is None:
                print("Warning: YAML file loaded as None")
                sys.exit(1)
        except yaml.YAMLError as e:
            print(f"Error parsing YAML file: {e}")
            sys.exit(1)
    
    # Extract JSON attributes
    json_attributes, nested_paths = extract_json_attributes(json_data)
    
    # Specifically handle management section
    if 'management' in json_data:
        mgmt_attrs, mgmt_nested = extract_json_attributes(json_data['management'])
        for attr in mgmt_attrs:
            if attr not in json_attributes:  # Avoid duplicates
                json_attributes.add(attr)
            if attr not in nested_paths:
                nested_paths[attr] = []
            if 'management' not in nested_paths[attr]:
                nested_paths[attr].append('management')
    
    # Extract YAML attributes
    yaml_models, tf_to_model = extract_yaml_attributes(yaml_data)
    
    # Compare JSON attributes to YAML schema
    matching_attrs = []
    missing_attrs = []
    match_types = {'model_name': 0, 'tf_name': 0, 'case_insensitive_model': 0, 'case_insensitive_tf': 0}
    
    # Skip these top-level keys that aren't expected in schema
    skip_keys = {'name', 'location'}
    
    for attr in sorted(json_attributes):
        if attr in skip_keys:
            continue
        
        is_in_yaml, match_type = is_attribute_in_yaml(attr, yaml_models, tf_to_model)
        
        if is_in_yaml:
            matching_attrs.append((attr, match_type))
            if match_type:
                match_types[match_type] += 1
        else:
            # Get value from JSON to help with suggested YAML entry
            value = None
            if attr in nested_paths.get(attr, []):
                # Direct attribute
                value = json_data.get(attr)
            elif 'management' in nested_paths.get(attr, []):
                # Nested in management
                if 'management' in json_data:
                    value = json_data['management'].get(attr)
            
            missing_attrs.append((attr, value, nested_paths.get(attr, [])))
    
    # Handle netflow settings separately
    netflow_attrs = []
    if 'management' in json_data and 'netflowSettings' in json_data['management']:
        netflow_settings = json_data['management']['netflowSettings']
        for key, value in netflow_settings.items():
            is_in_yaml, match_type = is_attribute_in_yaml(key, yaml_models, tf_to_model)
            
            if is_in_yaml:
                matching_attrs.append((key, match_type))
                if match_type:
                    match_types[match_type] += 1
            else:
                netflow_attrs.append((key, value))
    
    # Print results
    print(f"\n=== Comparison Results ===")
    print(f"Total JSON attributes: {len(json_attributes)}")
    print(f"Total YAML model_names: {len(yaml_models)}")
    print(f"Total YAML tf_names: {len(tf_to_model)}")
    
    print(f"\nFound {len(matching_attrs)} matching attributes:")
    print(f"  - By model_name: {match_types['model_name']}")
    print(f"  - By tf_name: {match_types['tf_name']}")
    print(f"  - By case-insensitive model_name: {match_types['case_insensitive_model']}")
    print(f"  - By case-insensitive tf_name: {match_types['case_insensitive_tf']}")
    
    print(f"\nFound {len(missing_attrs)} missing attributes:")
    for i, (attr, value, paths) in enumerate(sorted(missing_attrs, key=lambda x: x[0]), 1):
        paths_str = ", ".join(paths)
        print(f"{i}. {attr} (Paths: {paths_str})")
    
    if netflow_attrs:
        print(f"\nNetflow Settings Attributes (requires special handling):")
        for i, (attr, value) in enumerate(sorted(netflow_attrs, key=lambda x: x[0]), 1):
            print(f"{i}. {attr}: {value}")
            
    # Print sample of matched attributes for verification
    print(f"\nSample of matched attributes (first 10):")
    for i, (attr, match_type) in enumerate(matching_attrs[:10], 1):
        print(f"{i}. {attr} (matched by: {match_type})")
    
    # Optional: Print JSON attributes with their paths (for debugging)
    if False:  # Set to True to enable this output
        print("\n=== All JSON Attributes with Paths ===")
        for attr in sorted(json_attributes):
            paths_str = ", ".join(nested_paths.get(attr, []))
            print(f"{attr}: {paths_str}")


def suggest_yaml_entry(attr, value, paths):
    """
    Generate a suggested YAML entry for a missing attribute.
    """
    tf_name = camel_to_snake(attr)
    
    # Determine yaml_type based on value
    yaml_type = "String"  # Default
    if isinstance(value, bool):
        yaml_type = "Bool"
    elif isinstance(value, int):
        yaml_type = "Int64"
    elif isinstance(value, float):
        yaml_type = "Float64"
    elif isinstance(value, list):
        yaml_type = "List"
    elif isinstance(value, dict):
        yaml_type = "Object"
    
    # Generate example string
    example = str(value) if value is not None else ""
    
    if isinstance(value, bool):
        example = str(value).lower()  # Convert True/False to true/false for YAML
    
    # Create the YAML entry
    entry = [
        f"  - model_name: {attr}",
        f"    tf_name: {tf_name}",
        f"    type: {yaml_type}",
        f"    optional: true",
        f"    computed: true",
        f"    example: {example}"
    ]
    
    # Add ndfc_type for Bool
    if yaml_type == "Bool":
        entry.append("    ndfc_type: bool")
    
    # Add nested path if applicable
    if paths and len(paths) > 0:
        entry.append("    ndfc_nested:")
        for path in paths:
            entry.append(f"    - {path}")
    
    # Add description
    entry.append(f"    description: {attr} configuration parameter")
    
    return "\n".join(entry)


if __name__ == "__main__":
    main()
