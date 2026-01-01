# SOCTI Toolkit

A comprehensive Security Operations toolkit combining token separation, reputation scoring, and asset comparison, designed for detailed analysis in corporate environments. 

## Features

### 1. SepRep (Separator + Reputation)
A dual-mode tool for normalizing data and checking IoC reputation.
- **Normalization**: Clean and format lists of IPs, Domains, or Hashes from raw text (logs, emails, CSVs).
- **Reputation Checks**: 
    - **VirusTotal**: Fetch detection ratios, community scores, and threat categories.
    - **AbuseIPDB**: Check IP abuse confidence scores, Country, and ISP.
    - **Visual Feedback**: Real-time color-coded output (Red for Malicious, Green for Safe).
    - **Auto-Export**: Automatically saves detailed CSV reports with verdicts and threat details.

### 2. HostSplit (Asset Extraction & DNS)
A three-panel tool for parsing mixed logs and enriching asset data.
- **Asset Extraction**: Intelligently splits and classifies input text into Hostnames and IPs.
- **DNS Lookup**: Performs bulk Forward (Hostname -> IP) and Reverse (IP -> Hostname) DNS lookups.
    - **Silent Execution**: Runs `nslookup` in the background without popups.
    - **Security**: Strict input validation to prevent command injection.
- **Export**: Export parsed and enriched results to JSON or CSV.

### 3. Asset Comparator
Compare two datasets to identify discrepancies quickly.
- **Set Operations**: Find Common items, Unique to A, and Unique to B.
- **Normalization**: Auto-cleanup of inputs (whitespace trimming, deduplication).
- **Export**: Save results to CSV or JSON.

### 4. Proxy Support
Built for corporate networks with strict firewall rules.
- **Authenticated Proxy**: Configure HTTP/HTTPS proxy settings via the GUI "Proxy Settings" modal or `settings.json`.
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
    Edit `settings.json` or configure via the GUI "API Settings" button.

## Usage

### GUI Mode
Launch the main interface:
```bash
python gui.py
```
- **SepRep Tab**: Paste text, select "VirusTotal" or "AbuseIPDB" for reputation checks. Results are color-coded and auto-exported to CSV.
- **HostSplit Tab**: Paste mixed logs (e.g., `ServerA (192.168.1.5)`), click "Split Hosts / IPs". Then use "Lookup (DNS)" to resolve missing fields.
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
