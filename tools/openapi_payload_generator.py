#!/usr/bin/env python3
"""
OpenAPI Payload Generator

This script parses an OpenAPI specification to perform various operations such as:
- Generating complete POST payload examples for a given feature
- Listing available features in the OpenAPI spec
- Listing paths for a specific feature
- Handling complex schemas with discriminators to generate all possible payload variations

Usage:
    python openapi_payload_generator.py -openapi <openapi_file> [options]

Options:
    -payload <feature_name>    Generate payload examples for a specific feature
    -features                  List all features in the OpenAPI spec
    -post_endpoint <feature>   List all POST endpoints for a specific feature
    -output <file>             Write output to a file

Examples:
    python openapi_payload_generator.py -openapi manage.json -payload fabric -output fabric_payloads.json
    python openapi_payload_generator.py -openapi manage.json -features
    python openapi_payload_generator.py -openapi manage.json -post_endpoint fabric
"""

import json
import sys
import os
import argparse
from typing import Dict, List, Any, Optional, Set
from copy import deepcopy

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class OpenAPIPayloadGenerator:
    def __init__(self, spec_path: str):
        """Initialize the generator with an OpenAPI specification."""
        self.spec_path = spec_path
        self.spec = self._load_spec()
        self.schemas = self.spec.get('components', {}).get('schemas', {})
        self.resolved_refs = {}  # Cache for resolved references
        
    def _load_spec(self) -> Dict[str, Any]:
        """Load the OpenAPI specification from file."""
        with open(self.spec_path, 'r', encoding='utf-8') as f:
            if self.spec_path.lower().endswith(('.yaml', '.yml')):
                if not YAML_AVAILABLE:
                    raise ImportError("PyYAML is required to parse YAML files. Install with: pip install PyYAML")
                return yaml.safe_load(f)
            else:
                return json.load(f)
    
    def find_post_endpoints(self, feature_name: str) -> List[Dict[str, Any]]:
        """Find all POST endpoints related to the given feature."""
        endpoints = []
        paths = self.spec.get('paths', {})
        
        for path, methods in paths.items():
            if feature_name.lower() in path.lower():
                post_method = methods.get('post')
                if post_method:
                    endpoints.append({
                        'path': path,
                        'method': 'POST',
                        'operation': post_method,
                        'operationId': post_method.get('operationId', f"post_{path.strip('/')}")
                    })
        
        return endpoints
    
    def resolve_reference(self, ref: str) -> Dict[str, Any]:
        """Resolve a JSON Schema reference."""
        if ref in self.resolved_refs:
            return self.resolved_refs[ref]
        
        # Handle $ref format: #/components/schemas/SchemaName
        if ref.startswith('#/'):
            parts = ref[2:].split('/')
            result = self.spec
            for part in parts:
                result = result.get(part, {})
            
            self.resolved_refs[ref] = result
            return result
        
        return {}
    
    def resolve_schema(self, schema: Dict[str, Any], visited: Optional[Set[str]] = None) -> Dict[str, Any]:
        """Recursively resolve schema references and compositions."""
        if visited is None:
            visited = set()
        
        if not isinstance(schema, dict):
            return schema
        
        # Handle $ref
        if '$ref' in schema:
            ref = schema['$ref']
            if ref in visited:
                # Circular reference detected
                return {'type': 'object', 'description': f'Circular reference to {ref}'}
            
            visited.add(ref)
            resolved = self.resolve_reference(ref)
            result = self.resolve_schema(resolved, visited.copy())
            visited.remove(ref)
            return result
        
        # Handle allOf
        if 'allOf' in schema:
            merged = {'type': 'object', 'properties': {}, 'required': []}
            for sub_schema in schema['allOf']:
                resolved_sub = self.resolve_schema(sub_schema, visited.copy())
                if resolved_sub.get('type') == 'object':
                    merged['properties'].update(resolved_sub.get('properties', {}))
                    merged['required'].extend(resolved_sub.get('required', []))
                # Merge other properties
                for key, value in resolved_sub.items():
                    if key not in ['properties', 'required', 'type']:
                        merged[key] = value
            
            # Remove duplicate required fields
            merged['required'] = list(set(merged['required']))
            
            # Merge with any properties defined at this level
            if 'properties' in schema:
                merged['properties'].update(schema['properties'])
            if 'required' in schema:
                merged['required'].extend(schema['required'])
                merged['required'] = list(set(merged['required']))
            
            return merged
        
        # Handle oneOf - keep as special marker for payload generation
        if 'oneOf' in schema:
            result = deepcopy(schema)
            result['_oneOf_resolved'] = []
            for sub_schema in schema['oneOf']:
                resolved_sub = self.resolve_schema(sub_schema, visited.copy())
                result['_oneOf_resolved'].append(resolved_sub)
            return result
        
        # Handle anyOf
        if 'anyOf' in schema:
            result = deepcopy(schema)
            result['_anyOf_resolved'] = []
            for sub_schema in schema['anyOf']:
                resolved_sub = self.resolve_schema(sub_schema, visited.copy())
                result['_anyOf_resolved'].append(resolved_sub)
            return result
        
        # Handle array items
        if schema.get('type') == 'array' and 'items' in schema:
            schema_copy = deepcopy(schema)
            schema_copy['items'] = self.resolve_schema(schema['items'], visited.copy())
            return schema_copy
        
        # Handle object properties
        if schema.get('type') == 'object' and 'properties' in schema:
            schema_copy = deepcopy(schema)
            schema_copy['properties'] = {}
            for prop_name, prop_schema in schema['properties'].items():
                schema_copy['properties'][prop_name] = self.resolve_schema(prop_schema, visited.copy())
            return schema_copy
        
        # Return schema as-is if no special handling needed
        return deepcopy(schema)
    
    def generate_value(self, schema: Dict[str, Any], property_name: str = "") -> Any:
        """Generate a default/example value for a given schema."""
        if not isinstance(schema, dict):
            return schema
        
        # Check for example or default values
        if 'example' in schema:
            return schema['example']
        if 'default' in schema:
            return schema['default']
        
        schema_type = schema.get('type')
        
        if schema_type == 'string':
            if 'enum' in schema:
                return schema['enum'][0]
            elif 'format' in schema:
                format_type = schema['format']
                if format_type == 'date':
                    return "2023-01-01"
                elif format_type == 'date-time':
                    return "2023-01-01T00:00:00Z"
                elif format_type == 'email':
                    return "example@example.com"
                elif format_type == 'uri':
                    return "https://example.com"
                elif format_type == 'uuid':
                    return "550e8400-e29b-41d4-a716-446655440000"
                elif format_type == 'ipv4':
                    return "192.168.1.1"
                elif format_type == 'ipv6':
                    return "2001:db8::1"
            else:
                # Smart field name detection for common patterns
                property_lower = property_name.lower()
                description = schema.get('description', '').lower()
                
                # IP Address patterns
                if (property_lower.endswith('ip') or 
                    any(pattern in property_lower for pattern in ['ipaddress', 'ip_address', 'gateway', 'serverip']) or
                    (('ip' in property_lower or 'address' in property_lower) and 
                     not any(exclude in property_lower for exclude in ['range', 'prefix', 'mask', 'subnet', 'cidr', 'port', 'vlanid', 'loopbackid']))):
                    if 'ipv6' in property_lower or 'ipv6' in description:
                        return "2001:db8::1"
                    else:
                        return "192.168.1.1"
                
                # IP Range patterns (CIDR notation)
                if any(pattern in property_lower for pattern in ['range', 'subnet', 'cidr', 'prefix']) and 'ip' in property_lower:
                    if 'ipv6' in property_lower or 'ipv6' in description:
                        return "2001:db8::/64"
                    else:
                        return "192.168.0.0/24"
                
                # MAC Address patterns
                if 'mac' in property_lower:
                    return "00:11:22:33:44:55"
                
                # Port patterns
                if 'port' in property_lower and any(word in property_lower for word in ['tcp', 'udp', 'http', 'snmp', 'ssh']):
                    if 'https' in property_lower:
                        return 443
                    elif 'http' in property_lower:
                        return 80
                    elif 'ssh' in property_lower:
                        return 22
                    elif 'snmp' in property_lower:
                        return 161
                    else:
                        return 8080
                
                # VLAN patterns
                if 'vlan' in property_lower and 'id' in property_lower:
                    return 100
                
                # BGP ASN patterns
                if 'asn' in property_lower or 'as' in property_lower:
                    return "65001"
                
                # Time/duration patterns
                if any(pattern in property_lower for pattern in ['time', 'timer', 'timeout', 'interval', 'delay']):
                    if 'backup' in property_lower:
                        return "02:00"  # 2 AM for backup time
                    else:
                        return 30  # seconds/minutes
                
                # Key/password patterns
                if any(pattern in property_lower for pattern in ['key', 'password', 'secret', 'auth']):
                    return "secretKey123"
                
                # Name/identifier patterns
                if any(pattern in property_lower for pattern in ['name', 'id', 'identifier']) and 'ip' not in property_lower:
                    if 'template' in property_lower:
                        return "DefaultTemplate"
                    elif 'policy' in property_lower:
                        return "DefaultPolicy"
                    elif 'vrf' in property_lower:
                        return "default"
                    else:
                        return f"example_{property_name}" if property_name else "example_string"
                
                # Domain/hostname patterns
                if any(pattern in property_lower for pattern in ['domain', 'hostname', 'host', 'fqdn']):
                    return "example.com"
                
                # Interface patterns
                if 'interface' in property_lower:
                    if 'loopback' in property_lower:
                        return "loopback0"
                    elif 'ethernet' in property_lower:
                        return "Ethernet1/1"
                    else:
                        return "mgmt0"
                
                # Banner/message patterns
                if 'banner' in property_lower or 'message' in property_lower:
                    return "Welcome to the network device"
                
                # Version patterns
                if 'version' in property_lower:
                    return "1.0.0"
                
                # Algorithm patterns
                if 'algorithm' in property_lower:
                    return "sha256"
            
            # Default fallback for strings
            return f"example_{property_name}" if property_name else "example_string"
        
        elif schema_type == 'integer':
            # Check for specific integer patterns first
            property_lower = property_name.lower()
            
            # Port numbers
            if 'port' in property_lower:
                if 'https' in property_lower:
                    return 443
                elif 'http' in property_lower:
                    return 80
                elif 'ssh' in property_lower:
                    return 22
                elif 'snmp' in property_lower:
                    return 161
                else:
                    return 8080
            
            # VLAN IDs
            if 'vlan' in property_lower:
                return 100
            
            # Prefix lengths
            if 'prefix' in property_lower or 'mask' in property_lower:
                if 'ipv6' in property_lower:
                    return 64
                else:
                    return 24
            
            # MTU sizes
            if 'mtu' in property_lower:
                return 1500
            
            # Timer/timeout values
            if any(pattern in property_lower for pattern in ['time', 'timer', 'timeout', 'interval', 'delay']):
                return 30
            
            # Use schema constraints
            if 'minimum' in schema:
                return max(schema['minimum'], 1)
            elif 'maximum' in schema:
                return min(schema['maximum'], 100)
            return 42
        
        elif schema_type == 'number':
            # Latitude/longitude patterns
            property_lower = property_name.lower()
            if 'latitude' in property_lower:
                return 37.7749  # San Francisco latitude
            elif 'longitude' in property_lower:
                return -122.4194  # San Francisco longitude
            
            if 'minimum' in schema:
                return max(float(schema['minimum']), 1.0)
            elif 'maximum' in schema:
                return min(float(schema['maximum']), 100.0)
            return 42.0
        
        elif schema_type == 'boolean':
            return True
        
        elif schema_type == 'array':
            if 'items' in schema:
                item_value = self.generate_value(schema['items'], f"{property_name}_item")
                return [item_value]
            return []
        
        elif schema_type == 'object':
            if 'properties' in schema:
                obj = {}
                required_props = schema.get('required', [])
                
                for prop_name, prop_schema in schema['properties'].items():
                    # Always include required properties, optionally include others
                    if prop_name in required_props:
                        obj[prop_name] = self.generate_value(prop_schema, prop_name)
                    else:
                        # Include optional properties for completeness
                        obj[prop_name] = self.generate_value(prop_schema, prop_name)
                
                return obj
            return {}
        
        # Handle oneOf - just take the first option for value generation
        if '_oneOf_resolved' in schema:
            return self.generate_value(schema['_oneOf_resolved'][0], property_name)
        
        # Handle anyOf - just take the first option for value generation
        if '_anyOf_resolved' in schema:
            return self.generate_value(schema['_anyOf_resolved'][0], property_name)
        
        # Fallback
        return None
    
    def generate_discriminated_payloads(self, schema: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate all possible payloads for a schema, handling discriminated unions."""
        resolved_schema = self.resolve_schema(schema)
        
        # Check if this is a oneOf schema with discriminator
        if '_oneOf_resolved' in resolved_schema:
            discriminator = resolved_schema.get('discriminator', {})
            
            if discriminator:
                # Generate separate payloads for each discriminated type
                payloads = []
                property_name = discriminator.get('propertyName')
                mapping = discriminator.get('mapping', {})
                
                for type_value, type_ref in mapping.items():
                    # Resolve the specific type schema
                    type_schema = self.resolve_schema({'$ref': type_ref})
                    payload = self.generate_value(type_schema)
                    
                    # Ensure discriminator property is set correctly
                    if property_name and isinstance(payload, dict):
                        payload[property_name] = type_value
                    
                    payloads.append({
                        'type': type_value,
                        'description': f"Payload for {type_value} type",
                        'discriminator': {
                            'property': property_name,
                            'value': type_value
                        },
                        'payload': payload
                    })
                
                return payloads
            else:
                # oneOf without discriminator - generate variation for each option
                payloads = []
                for i, variant_schema in enumerate(resolved_schema['_oneOf_resolved']):
                    payload = self.generate_value(variant_schema)
                    payloads.append({
                        'type': f"variant_{i + 1}",
                        'description': f"Payload variant {i + 1}",
                        'payload': payload
                    })
                return payloads
        
        # Single schema - generate one payload
        payload = self.generate_value(resolved_schema)
        return [{
            'type': 'default',
            'description': "Default payload",
            'payload': payload
        }]
    
    def generate_payloads_for_feature(self, feature_name: str) -> Dict[str, Any]:
        """Generate all possible POST payloads for a given feature."""
        endpoints = self.find_post_endpoints(feature_name)
        
        if not endpoints:
            return {
                'error': f'No POST endpoints found for feature: {feature_name}',
                'available_paths': list(self.spec.get('paths', {}).keys())
            }
        
        results = {
            'feature': feature_name,
            'endpoints': []
        }
        
        for endpoint in endpoints:
            endpoint_result = {
                'path': endpoint['path'],
                'operationId': endpoint['operationId'],
                'description': endpoint['operation'].get('description', ''),
                'payloads': []
            }
            
            # Get request body schema
            request_body = endpoint['operation'].get('requestBody', {})
            content = request_body.get('content', {})
            
            # Look for JSON content
            json_content = content.get('application/json', {})
            if json_content and 'schema' in json_content:
                schema = json_content['schema']
                payloads = self.generate_discriminated_payloads(schema)
                endpoint_result['payloads'] = payloads
            
            results['endpoints'].append(endpoint_result)
        
        return results


def list_all_features(generator: OpenAPIPayloadGenerator, output_file: Optional[str] = None) -> Dict[str, Any]:
    """List all features found in the OpenAPI spec."""
    paths = generator.spec.get('paths', {})
    features = {}
    
    # Extract feature names from paths
    for path in paths:
        parts = [p for p in path.split('/') if p and not p.startswith('{')]
        if parts:
            # Use the first non-parameter part as the feature name
            feature = parts[0]
            if feature not in features:
                features[feature] = []
            features[feature].append(path)
    
    # Format results
    results = {
        'total_features': len(features),
        'features': []
    }
    
    for feature, paths in sorted(features.items()):
        feature_info = {
            'name': feature,
            'paths': sorted(paths),
            'endpoint_count': len(paths)
        }
        results['features'].append(feature_info)
    
    # Output results
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"Feature list written to: {output_file}")
    else:
        print(f"\nFound {len(features)} features in the OpenAPI spec:")
        for feature_info in results['features']:
            print(f"\n{feature_info['name']} ({feature_info['endpoint_count']} endpoints):")
            for path in feature_info['paths'][:5]:  # Show only first 5 paths
                print(f"  {path}")
            if len(feature_info['paths']) > 5:
                print(f"  ...and {len(feature_info['paths']) - 5} more endpoints")
    
    return results


def list_post_endpoints(generator: OpenAPIPayloadGenerator, feature_name: str, output_file: Optional[str] = None) -> Dict[str, Any]:
    """List all POST endpoints for a specific feature."""
    endpoints = generator.find_post_endpoints(feature_name)
    
    results = {
        'feature': feature_name,
        'endpoint_count': len(endpoints),
        'endpoints': []
    }
    
    for endpoint in endpoints:
        endpoint_info = {
            'path': endpoint['path'],
            'operationId': endpoint['operationId'],
            'summary': endpoint['operation'].get('summary', ''),
            'description': endpoint['operation'].get('description', '')
        }
        results['endpoints'].append(endpoint_info)
    
    # Output results
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"POST endpoints for '{feature_name}' written to: {output_file}")
    else:
        print(f"\nFound {len(endpoints)} POST endpoints for feature '{feature_name}':")
        for endpoint_info in results['endpoints']:
            print(f"\nPath: {endpoint_info['path']}")
            print(f"  Operation ID: {endpoint_info['operationId']}")
            if endpoint_info['summary']:
                print(f"  Summary: {endpoint_info['summary']}")
    
    return results


def generate_payloads(generator: OpenAPIPayloadGenerator, feature_name: str, output_file: Optional[str] = None) -> Dict[str, Any]:
    """Generate payloads for a specific feature."""
    results = generator.generate_payloads_for_feature(feature_name)
    
    if output_file:
        # Write results to output file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        # Write separate JSON files for each endpoint and payload
        output_dir = os.path.splitext(output_file)[0]
        os.makedirs(output_dir, exist_ok=True)
        
        for endpoint in results.get('endpoints', []):
            # Clean endpoint path for filename
            endpoint_name = endpoint['path'].replace('/', '_').replace('{', '').replace('}', '').strip('_')
            if not endpoint_name:
                endpoint_name = endpoint['operationId']
            
            # Write endpoint summary
            endpoint_file = os.path.join(output_dir, f"{endpoint_name}_summary.json")
            endpoint_data = {
                'path': endpoint['path'],
                'operationId': endpoint['operationId'],
                'description': endpoint['description'],
                'payload_count': len(endpoint['payloads']),
                'payload_types': [p['type'] for p in endpoint['payloads']]
            }
            with open(endpoint_file, 'w', encoding='utf-8') as f:
                json.dump(endpoint_data, f, indent=2, ensure_ascii=False)
            
            # Write individual payload files
            for i, payload in enumerate(endpoint['payloads']):
                if len(endpoint['payloads']) > 1:
                    payload_file = os.path.join(output_dir, f"{endpoint_name}_{payload['type']}_payload.json")
                else:
                    payload_file = os.path.join(output_dir, f"{endpoint_name}_payload.json")
                
                payload_data = {
                    'endpoint': endpoint['path'],
                    'operationId': endpoint['operationId'],
                    'type': payload['type'],
                    'description': payload['description'],
                    'discriminator': payload.get('discriminator'),
                    'payload': payload['payload']
                }
                with open(payload_file, 'w', encoding='utf-8') as f:
                    json.dump(payload_data, f, indent=2, ensure_ascii=False)
        
        print(f"Generated payloads for feature '{feature_name}'")
        print(f"Combined results written to: {output_file}")
        print(f"Individual payload files written to: {output_dir}/")
        print(f"Total files created: {len(os.listdir(output_dir)) + 1}")
    else:
        # Print summary
        if 'endpoints' in results:
            print(f"\nGenerated payloads for feature '{feature_name}'")
            for endpoint in results['endpoints']:
                print(f"\nEndpoint: {endpoint['path']}")
                print(f"  Operation ID: {endpoint['operationId']}")
                print(f"  Payloads generated: {len(endpoint['payloads'])}")
                for payload in endpoint['payloads']:
                    print(f"    - {payload['type']}: {payload['description']}")
                    if payload.get('discriminator'):
                        disc = payload['discriminator']
                        print(f"      Discriminator: {disc['property']} = {disc['value']}")
    
    return results


def main():
    """Main function to run the payload generator with command line arguments."""
    parser = argparse.ArgumentParser(description='OpenAPI Payload Generator and Explorer')
    parser.add_argument('-openapi', required=True, help='Path to OpenAPI spec file')
    parser.add_argument('-payload', help='Generate payload examples for a specific feature')
    parser.add_argument('-features', action='store_true', help='List all features in the OpenAPI spec')
    parser.add_argument('-post_endpoint', help='List all POST endpoints for a specific feature')
    parser.add_argument('-output', help='Write output to a file')
    
    args = parser.parse_args()
    
    # Check if OpenAPI spec file exists
    if not os.path.exists(args.openapi):
        print(f"Error: OpenAPI spec file '{args.openapi}' not found.")
        sys.exit(1)
    
    try:
        generator = OpenAPIPayloadGenerator(args.openapi)
        
        # Check if at least one action was specified
        if not (args.payload or args.features or args.post_endpoint):
            parser.print_help()
            print("\nError: You must specify at least one action (-payload, -features, or -post_endpoint).")
            sys.exit(1)
        
        # Execute requested action
        if args.features:
            list_all_features(generator, args.output)
        
        if args.post_endpoint:
            list_post_endpoints(generator, args.post_endpoint, args.output)
        
        if args.payload:
            generate_payloads(generator, args.payload, args.output)
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
