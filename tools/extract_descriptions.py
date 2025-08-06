#!/usr/bin/env python3
import yaml
import json
import os
import argparse
from typing import Dict, List, Optional, Any

def extract_model_names_from_fabric_yaml(file_path: str) -> List[Dict[str, Any]]:
    """Extract all model_name values and their attributes from the fabric.yaml file."""
    with open(file_path, 'r') as file:
        yaml_content = yaml.safe_load(file)
    
    model_attrs = []
    if 'resource' in yaml_content and 'attributes' in yaml_content['resource']:
        for attr in yaml_content['resource']['attributes']:
            if 'model_name' in attr:
                model_attrs.append(attr)
    
    return model_attrs, yaml_content

def search_description_in_schemas(json_obj: Any, model_name: str) -> Optional[str]:
    """
    Recursively search for a property with the given model_name in the JSON structure
    and return its description if found.
    """
    if isinstance(json_obj, dict):
        # If this is a property definition matching our model_name
        if model_name in json_obj and isinstance(json_obj[model_name], dict):
            if "description" in json_obj[model_name]:
                return json_obj[model_name]["description"]
        
        # Search in all values
        for key, value in json_obj.items():
            # Special handling for schema properties
            if key == "properties" and isinstance(value, dict):
                if model_name in value and isinstance(value[model_name], dict):
                    if "description" in value[model_name]:
                        return value[model_name]["description"]
            
            # Recursive search
            result = search_description_in_schemas(value, model_name)
            if result:
                return result
    
    elif isinstance(json_obj, list):
        for item in json_obj:
            result = search_description_in_schemas(item, model_name)
            if result:
                return result
    
    return None

def update_fabric_yaml_with_descriptions(yaml_content, model_descriptions):
    """Update fabric.yaml with descriptions from model_descriptions."""
    attributes = yaml_content['resource']['attributes']
    descriptions_added = 0
    descriptions_already_exist = 0
    
    for attr in attributes:
        if 'model_name' in attr:
            model_name = attr['model_name']
            # Only add description if it doesn't already exist
            if 'description' not in attr:
                if model_name in model_descriptions:
                    attr['description'] = model_descriptions[model_name]
                    descriptions_added += 1
            else:
                descriptions_already_exist += 1
    
    return yaml_content, descriptions_added, descriptions_already_exist

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Extract and update descriptions from OpenAPI spec to YAML definition file')
    parser.add_argument('-openapi', required=True, help='Path to the OpenAPI specification JSON file (e.g., manage.json)')
    parser.add_argument('-definition', required=True, help='Path to the YAML definition file (e.g., fabric.yaml)')
    args = parser.parse_args()
    
    # Use the provided paths
    manage_json_path = args.openapi
    fabric_yaml_path = args.definition
    model_descriptions_path = os.path.join('/tmp', 'model_descriptions.json')
    
    # Extract model names from fabric.yaml
    print("Extracting model attributes from fabric.yaml...")
    model_attrs, yaml_content = extract_model_names_from_fabric_yaml(fabric_yaml_path)
    model_names = [attr['model_name'] for attr in model_attrs]
    print(f"Found {len(model_names)} model names in fabric.yaml")
    
    # Load manage.json
    print("Loading manage.json...")
    with open(manage_json_path, 'r') as file:
        manage_json = json.load(file)
    
    # Extract components/schemas section which contains most definitions
    components_schemas = manage_json.get("components", {}).get("schemas", {})
    
    # Create dictionary with model_name as key and description as value
    model_descriptions = {}
    print("Finding descriptions in manage.json...")
    
    for attr in model_attrs:
        model_name = attr['model_name']
        # First check if the model already has a description in fabric.yaml
        if 'description' in attr:
            model_descriptions[model_name] = attr['description']
            continue
        
        # Search in the components/schemas section first (most definitions are here)
        description = search_description_in_schemas(components_schemas, model_name)
        
        # If not found, search in the entire manage.json
        if not description:
            description = search_description_in_schemas(manage_json, model_name)
        
        if description:
            model_descriptions[model_name] = description
    
    # Print results
    print(f"Found descriptions for {len(model_descriptions)} out of {len(model_names)} model names")
    
    # Save to output file
    with open(model_descriptions_path, 'w') as file:
        json.dump(model_descriptions, file, indent=2, sort_keys=True)
    
    print(f"Descriptions saved to {model_descriptions_path}")
    
    # Now update fabric.yaml with descriptions
    print("\nUpdating fabric.yaml with descriptions...")
    with open(fabric_yaml_path, 'r') as file:
        yaml_content = yaml.safe_load(file)
    
    # Update the yaml_content with descriptions
    updated_yaml, added, already_exist = update_fabric_yaml_with_descriptions(yaml_content, model_descriptions)
    
    # Write updated yaml back to file
    # Use a safe_dump with proper configuration to match original format
    with open(fabric_yaml_path, 'w') as file:
        yaml.dump(updated_yaml, file, default_flow_style=False, sort_keys=False)
    
    print(f"Added descriptions to {added} attributes")
    print(f"Found {already_exist} attributes that already had descriptions")
    print(f"Updated fabric.yaml file saved")
    print(f"Intermediate file written to {model_descriptions_path}")

if __name__ == "__main__":
    main()
