# Phisher@Info Tool

**Phisher@Info** is a comprehensive URL analysis tool designed to help users detect phishing, malware, and other potential threats in URLs. It provides several checks, including URL validation, reachability, redirection, malware detection, SSL certificate validation, and more. The results are saved in a Word document for later reference.

---

## Features

- **URL Validation**: Checks if the given string is a valid URL.
- **URL Reachability**: Determines if the URL is accessible.
- **URL Redirection**: Identifies whether the URL redirects to another location.
- **HTTPS Verification**: Checks if the URL uses a secure HTTPS connection.
- **URL Path Analysis**: Analyzes the URL path for specific components.
- **Query Parameters Extraction**: Extracts query parameters from the URL.
- **Fragment Identifier Extraction**: Retrieves the fragment identifier from the URL.
- **Malware and Phishing Detection**: Scans the webpage for malicious or phishing content.
- **SSL Certificate Check**: Examines the SSL certificate for important security details.
- **Report Generation**: Saves the analysis results in a Word document.

---

## Installation

### Prerequisites

Ensure you have Python 3.12 or higher installed on your system.

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/samcm22/phisher-info.git
   cd phisher-info
   pip install requests bs4 art docx
## Usage
**python phisher_info.py**

### Choose an option from the menu:

Enter 1: To analyze a URL.
Enter 2: To view information about the tool.
Enter the URL to analyze when prompted.
View the results on the screen. The results are also saved in a Word document at the location you specify.


### Example Output
----CHECKING---PHISHING--URL---

Checking phishing URL: Safe Website: This website appears to be safe.

------URL----VALID---CHECK----

The URL is valid.
Is Valid URL: True

-----URL----REACHABLE---CHECK----

Is URL Reachable: True

----URL---REDIRECTION---CHECK-----

Redirected URL: None

-----URL---HTTP---HTTPS---CHECK----

Is URL using HTTPS: True

-----URL---PATH----CHECK------

Contains Path: False

-----URL---QUERY---PARAMETERS----

Query Parameters: {}

-----URL---FRAGMENT---IDENTIFIER------

Fragment Identifier: 

-----------------malware----info--------------

No malware or phishing content detected.

-------SSL---CERTIFICATE---DETAIL------

Subject: [...]

Issuer: [...]

Expiry Date: [...]

Serial Number: [...]

Public Key: [...]

Results saved to: C:\sam\result.docx

### Word Document Output

--------PHISHER@INFO---REPORT----

URL Check Results

URL: https://example.com

Valid URL: True

URL Reachable: True

Redirected URL: None

Using HTTPS: True

Contains Path: False

Query Parameters: {}

Fragment Identifier: 

Contains Malware: False


Thank you for using Phisher@Info tools!


### Contributing
Contributions are welcome! If you encounter any issues or have suggestions, feel free to open an issue or submit a pull request.

### License
This project is licensed under the MIT License. See the LICENSE file for details.

### Acknowledgements
Developed by👉 Sam@cm.

Powered by Python libraries like requests, BeautifulSoup, art, and docx.
### Disclaimer
This tool is for educational and research purposes only. Use it responsibly and ensure compliance with applicable laws when analyzing URLs.
