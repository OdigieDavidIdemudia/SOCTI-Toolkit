# SOCTI Toolkit

A comprehensive Security Operations toolkit combining token separation, reputation scoring, and asset comparison, designed for detailed analysis in corporate environments. 

## Features

### 1. SepRep (Separator + Reputation)
A dual-mode tool for normalizing data and checking IoC reputation.
- **Normalization**: Clean and format lists of IPs, Domains, or Hashes from raw text (logs, emails, CSVs).
- **Reputation Checks**: 
    - **VirusTotal**: Fetch detection ratios and community scores.
    - **AbuseIPDB**: Check IP abuse confidence scores.
    - **CSV Reports**: Generates detailed reports with Country, ISP, and Verdicts.

### 2. Asset Comparator
Compare two datasets to identify discrepancies quickly.
- **Set Operations**: Find Common items, Unique to A, and Unique to B.
- **Normalization**: Auto-cleanup of inputs (whitespace trimming, deduplication).
- **Export**: Save results to CSV or JSON.

### 3. Proxy Support
Built for corporate networks with strict firewall rules.
- **Authenticated Proxy**: specific settings in `settings.json` to route traffic through corporate proxies.
- **SSL Handling**: Configured to handle decrypting proxies gracefully.

## Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/StartYourOwn/SOCTI-Toolkit.git
    cd SOCTI-Toolkit
    ```

2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure Settings**:
    Copy the example settings file and add your API keys/Proxy details.
    ```bash
    cp settings.json.example settings.json
    ```
    Edit `settings.json`:
    ```json
    {
        "proxy": {
            "host": "proxy.example.com",
            "port": "8080",
            "username": "user",
            "password": "password"
        },
        "api_keys": {
            "vt_key": "YOUR_VIRUSTOTAL_KEY",
            "abuse_key": "YOUR_ABUSEIPDB_KEY"
        }
    }
    ```

## Usage

### GUI Mode
Launch the main interface:
```bash
python gui.py
```
- **SepRep Tab**: Paste text, select "VirusTotal" or "AbuseIPDB" to check reputation, or just click "Convert" to format.
- **Asset Comparator Tab**: Upload files or paste lists to compare.

### CLI Mode (Separator Only)
Quickly format lists from the command line:
```bash
python main.py "ip1 ip2 ip3" --sep ","
# Output: ip1,ip2,ip3
```

## Building Portable Executable
To create a standalone `.exe`:
```bash
pyinstaller --onefile --windowed --name SepX gui.py
```
The executable will be in the `dist/` folder.

## License
MIT License
