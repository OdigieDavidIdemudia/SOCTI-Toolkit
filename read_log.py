
try:
    with open('error.log', 'r', encoding='utf-16') as f:
        print(f.read())
except Exception as e:
    print(f"Failed utf-16: {e}")
    try:
        with open('error.log', 'r', encoding='utf-8', errors='ignore') as f:
            print(f.read())
    except Exception as e2:
        print(f"Failed utf-8: {e2}")
