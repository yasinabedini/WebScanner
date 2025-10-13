### ## requirement : 
  1- Install Python (Last version)
  2- pip install requirement.txt

## Structure

WebScanner 
|
|--- tools
|      |---- nuclei-templates
|
|--- ScannerV2.py
|--- ScannerV3.py
|--- DomainV1.py 


# WebScanner

------------


## Scan
Scan & Fuzzing On Domains
Example  : 
  ### Python ScannerV2.py <Domain>
  Python ScannerV3.py <Domain>

<br>
## Recon 
  Recon SubDomain, Find Live SubDomain

  Example : 
  ### python SubdomainPortScanner.py <domain> [scan_mode]

  Scan Modes:
    common   - Scan top 20 common ports (default)
    extended - Scan top 1000 ports + common services
    full     - Scan all 65535 ports (slow)
