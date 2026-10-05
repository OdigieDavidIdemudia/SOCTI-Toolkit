import re
from lxml import etree as ET
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment

def preprocess_xml(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    # 1. Strip leading banner
    vpmapp_idx = content.find('<vpmapp>')
    if vpmapp_idx != -1:
        content = content[vpmapp_idx:]
        
    # 2. Fix unescaped ampersands (e.g., HR & Admin -> HR &amp; Admin)
    # Match & that is not followed by a valid entity reference
    content = re.sub(r'&(?!amp;|lt;|gt;|quot;|apos;|#\d+;)', '&amp;', content)
    
    return content

def build_object_tables(root):
    objects = {}
    
    # Extract condition objects
    cond_objs = root.find('.//conditionObjects')
    if cond_objs is None:
        return objects

    for child in cond_objs:
        tag = child.tag
        name = child.get('name')
        if not name:
            continue
            
        obj_data = {'tag': tag, 'raw_element': child, 'referenced_by_rules': 0, 'referenced_by_objects': 0}
        
        if tag == 'ipobject':
            val = child.get('value', '')
            obj_data['leaf_values'] = [{'value': val, 'leaf_type': 'ip'}]
        elif tag == 'a-url':
            val = child.get('d') or child.get('h') or ''
            obj_data['leaf_values'] = [{'value': val, 'leaf_type': 'url'}]
        elif tag == 'group':
            val = child.get('group-base') or child.get('realm-name') or name
            obj_data['leaf_values'] = [{'value': val, 'leaf_type': 'identity'}]
        elif tag == 'comb-obj':
            # Composite object
            children = [c.get('n') for c in child.findall('.//c-l-1') if c.get('n')]
            obj_data['children'] = children
        elif tag.startswith('categorylist'):
            # e.g., categorylist4
            sel_list = [c.text for c in child.findall('.//sel/i') if c.text]
            obj_data['children'] = sel_list
        else:
            obj_data['leaf_values'] = [{'value': name, 'leaf_type': 'unknown'}]
            
        objects[name] = obj_data

    # Extract vpm-cat nodes
    for vpm_cat in root.findall('.//vpm-cat'):
        for node in vpm_cat.findall('.//node'):
            name = node.get('n')
            if not name:
                continue
            
            ul = node.get('u-l', '')
            leafs = []
            if ul:
                # space delimited list of domains/IPs
                for item in ul.split():
                    leafs.append({'value': item, 'leaf_type': 'category-member'})
                    
            child_refs = [c.get('n') for c in node.findall('.//child') if c.get('n')]
            
            objects[name] = {
                'tag': 'vpm-cat-node',
                'raw_element': node,
                'leaf_values': leafs,
                'children': child_refs,
                'referenced_by_rules': 0,
                'referenced_by_objects': 0
            }
            
    return objects

def resolve_object(name, objects, visited_names=None):
    if visited_names is None:
        visited_names = set()
        
    if not name:
        return []
        
    if name == 'Any':
        return [{'value': 'Any', 'leaf_type': 'wildcard'}]
        
    if name in visited_names:
        return [{'value': name, 'leaf_type': 'circular_reference'}]
        
    visited_names.add(name)
    
    if name not in objects:
        return [{'value': name, 'leaf_type': 'unresolved'}]
        
    obj = objects[name]
    leafs = list(obj.get('leaf_values', []))
    
    if 'children' in obj:
        for child_name in obj['children']:
            if child_name in objects:
                objects[child_name]['referenced_by_objects'] += 1
            child_leafs = resolve_object(child_name, objects, visited_names.copy())
            leafs.extend(child_leafs)
            
    return leafs

def format_resolved_values(leaf_values, truncate_limit=25):
    if not leaf_values:
        return ""
    
    # Deduplicate and extract just the values
    vals = []
    seen = set()
    for l in leaf_values:
        v = l['value']
        if v not in seen:
            seen.add(v)
            vals.append(v)
            
    if truncate_limit and len(vals) > truncate_limit:
        rem = len(vals) - truncate_limit
        return ", ".join(vals[:truncate_limit]) + f" ... (+{rem} more)"
        
    return ", ".join(vals)

def run_vpm_review(file_path, output_path, truncate_limit=25):
    # 1. Preprocess XML
    xml_str = preprocess_xml(file_path)
    
    # 2. Parse XML
    try:
        parser = ET.XMLParser(recover=True)
        root = ET.fromstring(xml_str.encode('utf-8'), parser=parser)
    except ET.ParseError as e:
        raise ValueError(f"XML Parsing Error: {e}")
        
    # 3. Build Object Tables
    objects = build_object_tables(root)
    
    # 4. Extract Policies
    policies = []
    flags = []
    
    layers = root.findall('.//layers/layer')
    
    for layer in layers:
        layer_type = layer.get('layertype', 'Unknown')
        layer_enabled = layer.get('disabled', 'false').lower() == 'false'
        layer_name = layer.find('n')
        layer_name = layer_name.text if layer_name is not None else layer_type
        
        # Track duplicate detection within layer
        layer_rules_fingerprints = set()
        
        rules = layer.findall('.//rowItem')
        for rule in rules:
            rule_no = rule.get('num', '?')
            rule_enabled = rule.get('enabled', 'true').lower() == 'true'
            
            # Map columns via id attribute
            cols = rule.findall('col')
            col_map = {}
            for col in cols:
                cid = col.get('id')
                val = col.get('v') or col.get('n') or col.text or ''
                if val and val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                col_map[cid] = val
                
            so = col_map.get('so', 'Any')
            de = col_map.get('de', 'Any')
            se = col_map.get('se', 'Any')
            ti = col_map.get('ti', 'Any')
            ac = col_map.get('ac', 'None')
            tr = col_map.get('tr', 'None')
            ep = col_map.get('ep', 'None')
            co = col_map.get('co', '')
            
            # Record object usage
            if so != 'Any' and so in objects: objects[so]['referenced_by_rules'] += 1
            if de != 'Any' and de in objects: objects[de]['referenced_by_rules'] += 1
            
            resolved_so = resolve_object(so, objects)
            resolved_de = resolve_object(de, objects)
            
            # Check Circular Refs
            circ = [x for x in resolved_so + resolved_de if x['leaf_type'] == 'circular_reference']
            if circ:
                flags.append([layer_name, rule_no, "Circular Reference", f"Loop detected in {circ[0]['value']}"])
                
            so_display = format_resolved_values(resolved_so, truncate_limit)
            de_display = format_resolved_values(resolved_de, truncate_limit)
            
            # Check Flags
            if ac == 'Allow' and (so == 'Any' or de == 'Any'):
                flags.append([layer_name, rule_no, "Broad Allow", "Action=Allow with Source or Destination=Any"])
            
            if not rule_enabled or not layer_enabled:
                flags.append([layer_name, rule_no, "Disabled Rule", "Rule or Layer is disabled"])
                
            if not co.strip():
                flags.append([layer_name, rule_no, "No Comment", "Documentation gap"])
                
            fingerprint = f"{so_display}_{de_display}_{se}_{ac}"
            if fingerprint in layer_rules_fingerprints:
                flags.append([layer_name, rule_no, "Duplicate Rule", "Identical resolved conditions in this layer"])
            else:
                layer_rules_fingerprints.add(fingerprint)
                
            # Suggestion ranking:
            # 1: specific src + specific dst
            # 2: specific src OR specific dst
            # 3: Any/Any
            if so != 'Any' and de != 'Any':
                suggestion = 1
            elif so == 'Any' and de == 'Any':
                suggestion = 3
            else:
                suggestion = 2
                
            policies.append([
                layer_name, layer_type, layer_enabled, rule_no, rule_enabled,
                so, so_display, resolved_so[0]['leaf_type'] if resolved_so else '',
                de, de_display, resolved_de[0]['leaf_type'] if resolved_de else '',
                se, ti, ac, tr, ep, co, suggestion
            ])

    # 5. Build Output Excel
    wb = Workbook()
    
    # Styles (Matching Asset Compliance Theme)
    bold_font = Font(bold=True)
    center_align = Alignment(horizontal="center")
    
    # --- Policies Sheet ---
    ws_pol = wb.active
    ws_pol.title = "Raw Policies"
    pol_headers = ["Layer Name", "Layer Type", "Layer Enabled", "Rule #", "Rule Enabled", 
                   "Source (raw)", "Source (resolved)", "Source Type", "Destination (raw)", 
                   "Destination (resolved)", "Destination Type", "Service", "Time", "Action", 
                   "Track", "Enforcement Point", "Comment", "Suggested Rank"]
    
    ws_pol.append(pol_headers)
    for row in policies:
        ws_pol.append(row)
        
    for cell in ws_pol[1]:
        cell.font = bold_font

    # --- Policy Overview (Simplified) ---
    ws_overview = wb.create_sheet("Policy Overview")
    ws_overview.append(["Policy / Layer Name", "Rule #", "Client / Source", "Target / Category", "Service / Protocol", "Action", "Comment", "Status"])
    
    for row in policies:
        layer_name = row[0]
        rule_no = row[3]
        client_src = row[6] or row[5] # display or raw
        target_dst = row[9] or row[8]
        service = row[11]
        action = row[13]
        comment = row[16]
        
        status = "Active"
        if not row[2] or not row[4]:
            status = "Disabled"
            
        ws_overview.append([layer_name, rule_no, client_src, target_dst, service, action, comment, status])
        
    for cell in ws_overview[1]: cell.font = bold_font

    # --- Grouped By Category ---
    ws_by_cat = wb.create_sheet("By Category")
    ws_by_cat.append(["Target / Category", "Policy / Layer Name", "Rule #", "Client / Source", "Service / Protocol", "Action", "Comment", "Status"])
    
    # Sort policies by Target/Category to group them
    # target is row[9] (de_display) or row[8] (de raw)
    sorted_policies = sorted(policies, key=lambda r: (r[9] or r[8] or "").lower())
    
    for row in sorted_policies:
        layer_name = row[0]
        rule_no = row[3]
        client_src = row[6] or row[5]
        target_dst = row[9] or row[8]
        service = row[11]
        action = row[13]
        comment = row[16]
        status = "Active" if (row[2] and row[4]) else "Disabled"
        
        ws_by_cat.append([target_dst, layer_name, rule_no, client_src, service, action, comment, status])
        
    for cell in ws_by_cat[1]: cell.font = bold_font

    # --- Categories Sheet ---
    ws_cat = wb.create_sheet("Categories")
    ws_cat.append(["Category Name", "Direct Member Count", "Resolved Member Count", "Child Categories", "Used In Rules (Direct)"])
    
    for k, v in objects.items():
        if v['tag'] == 'vpm-cat-node':
            direct_count = len(v.get('leaf_values', []))
            resolved_members = resolve_object(k, objects)
            resolved_count = len(set(x['value'] for x in resolved_members if x['leaf_type'] != 'circular_reference'))
            child_cats = ", ".join(v.get('children', []))
            usage = v['referenced_by_rules']
            ws_cat.append([k, direct_count, resolved_count, child_cats, usage])
            
    for cell in ws_cat[1]: cell.font = bold_font

    # --- Objects Sheet ---
    ws_obj = wb.create_sheet("Objects")
    ws_obj.append(["Object Name", "Object Type", "Resolved Values", "Direct Rule References", "Object References"])
    
    unused_objects = []
    
    for k, v in objects.items():
        if v['tag'] != 'vpm-cat-node': # exclude raw vpm-cat nodes from general objects
            resolved_members = resolve_object(k, objects)
            full_list = format_resolved_values(resolved_members, truncate_limit=None)
            rule_refs = v['referenced_by_rules']
            obj_refs = v['referenced_by_objects']
            
            ws_obj.append([k, v['tag'], full_list, rule_refs, obj_refs])
            
            if rule_refs == 0 and obj_refs == 0:
                unused_objects.append([k, v['tag'], full_list])
                
    for cell in ws_obj[1]: cell.font = bold_font

    # --- Unused Objects Sheet ---
    ws_un = wb.create_sheet("Unused Objects")
    ws_un.append(["Object Name", "Object Type", "Resolved Values"])
    for row in unused_objects:
        ws_un.append(row)
    for cell in ws_un[1]: cell.font = bold_font
        
    # --- Review Flags Sheet ---
    ws_flag = wb.create_sheet("Review Flags")
    ws_flag.append(["Layer Name", "Rule #", "Flag", "Detail"])
    for row in flags:
        ws_flag.append(row)
    for cell in ws_flag[1]: cell.font = bold_font

    # --- Summary Sheet ---
    ws_sum = wb.create_sheet("Summary", 0) # Put first
    ws_sum.append(["Metric", "Value"])
    ws_sum.append(["Total Layers", len(layers)])
    ws_sum.append(["Total Rules", len(policies)])
    ws_sum.append(["Enabled Rules", sum(1 for p in policies if p[4])])
    ws_sum.append(["Disabled Rules", sum(1 for p in policies if not p[4])])
    ws_sum.append(["Total Objects Defined", len(objects)])
    ws_sum.append(["Total Objects Unused", len(unused_objects)])
    ws_sum.append(["Total Categories", sum(1 for k,v in objects.items() if v['tag']=='vpm-cat-node')])
    ws_sum.append(["Rules Flagged for Review", len(set(f"{f[0]}_{f[1]}" for f in flags))])
    
    for cell in ws_sum[1]: cell.font = bold_font
    ws_sum.column_dimensions['A'].width = 30
    ws_sum.column_dimensions['B'].width = 15

    # Auto-adjust some widths
    for sheet in wb.sheetnames:
        if sheet != "Summary":
            ws = wb[sheet]
            for col in ['A', 'B', 'C', 'F', 'G', 'I', 'J']:
                ws.column_dimensions[col].width = 20

    wb.save(output_path)
    return True
