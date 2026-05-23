import pm_engine

def get_location_mock(ip):
    # Mocking external API
    if ip == '192.168.1.1':
        return {"countryCode": "US", "lat": 40.7128, "lon": -74.0060, "city": "New York"}
    else:
        return {"countryCode": "NG", "lat": 6.5244, "lon": 3.3792, "city": "Lagos"}

eng = pm_engine.PMLogEngine()
eng.get_location = get_location_mock

df, mismatches, impossible_travel, ext_ips = eng.parse_logs(r'C:\Users\DELL\Downloads\PM_LOG_FORWARDING.xlsx')

print(f"Mismatches: {len(mismatches)}")
print(f"Impossible Travels: {len(impossible_travel)}")
