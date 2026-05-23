import pandas as pd
import json

try:
    df = pd.read_excel(r'C:\Users\DELL\Downloads\PM_LOG_FORWARDING.xlsx', header=1)
    with open('output.txt', 'w') as f:
        f.write("COLUMNS:\n")
        f.write(json.dumps(list(df.columns)) + "\n")
        f.write("DATA:\n")
        f.write(json.dumps(df.head(2).fillna("").astype(str).to_dict('records'), indent=2))
except Exception as e:
    with open('output.txt', 'w') as f:
        f.write(str(e))
