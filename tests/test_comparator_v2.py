import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from comparator import ComparisonEngine
import pandas as pd
import os

# Mock data
list_a = [
    {'hostname': 'host1', 'ip_or_hash': '1.1.1.1'},
    {'hostname': 'host2', 'ip_or_hash': '2.2.2.2'},
    {'hostname': 'host3', 'ip_or_hash': '3.3.3.3'}
]

list_b = [
    {'hostname': 'host1-diff', 'ip_or_hash': '1.1.1.1'}, # Same IP (Match)
    {'hostname': 'host4', 'ip_or_hash': '4.4.4.4'}       # Unique
]

def test_compare_logic():
    engine = ComparisonEngine()
    
    # Test without onboarded check
    res = engine.compare(list_a, list_b, check_onboarded=False)
    
    assert len(res['common']) == 1
    assert res['common'][0]['ip_or_hash'] == '1.1.1.1'
    assert res['common'][0]['comparison_result'] == 'common'
    
    assert len(res['unique_to_a']) == 2 # 2.2.2.2, 3.3.3.3
    assert len(res['unique_to_b']) == 1 # 4.4.4.4

def test_compare_logic_onboarded():
    engine = ComparisonEngine()
    
    # Test WITH onboarded check
    res = engine.compare(list_a, list_b, check_onboarded=True)
    
    # Common item should be Onboarded: Yes
    assert res['common'][0]['onboarded'] == 'Yes'
    
    # Unique items should be Onboarded: No
    assert res['unique_to_a'][0]['onboarded'] == 'No'
    assert res['unique_to_b'][0]['onboarded'] == 'No'

def test_pandas_excel_read():
    # create a dummy excel
    df = pd.DataFrame([
        {'Hostname': 'h1', 'IP_OR_HASH ': ' 10.10.10.10 '}, 
        {'Hostname': 'h2', 'IP_OR_HASH ': '20.20.20.20'}
    ])
    df.to_excel('test_assets.xlsx', index=False)
    
    # Read back and normalize like in GUI
    read_df = pd.read_excel('test_assets.xlsx')
    read_df.columns = [str(c).lower().strip().replace(' ', '_') for c in read_df.columns]
    
    assert 'hostname' in read_df.columns
    assert 'ip_or_hash' in read_df.columns
    
    # Check value cleaning logic (simulated from GUI)
    lines = []
    for _, row in read_df.iterrows():
        i = str(row.get('ip_or_hash', '')).strip()
        lines.append(i)
        
    assert '10.10.10.10' in lines
    assert '20.20.20.20' in lines
    
    # Cleanup
    try:
        os.remove('test_assets.xlsx')
    except:
        pass

if __name__ == "__main__":
    # If run directly
    try:
        test_compare_logic()
        test_compare_logic_onboarded()
        test_pandas_excel_read()
        print("All tests passed!")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Test failed: {repr(e)}")
        exit(1)
