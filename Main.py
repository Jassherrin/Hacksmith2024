import re
import requests
import base64

# Common phishing keywords
PHISHING_KEYWORDS = [
    "urgent", "verify your account", "click here", "prize", "payment", 
    "congratulations", "lottery", "refund", "password reset"
]

# VirusTotal API key (replace 'YOUR_API_KEY' with your VirusTotal API key)
VIRUSTOTAL_API_KEY = "5b89e7cd102bda5e834c6816cd892b996d2df3f9336479acccab458950e542b5" #YOUR_API_KEY_HERE

VIRUSTOTAL_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_URL_REPORT = "https://www.virustotal.com/api/v3/analyses/{}"

# Function to check suspicious keywords in messages
def check_keywords(message):
    for keyword in PHISHING_KEYWORDS:
        if keyword in message.lower():
            return True, f"⚠️ Suspicious keyword detected: '{keyword}'"
    return False, "✅ No suspicious keywords found."

# Function to check if a link is shortened
def check_shortened_links(link):
    if re.match(r"(https?://)?(bit\.ly|tinyurl\.com|t\.co|goo\.gl|short\.io)", link):
        return True, "⚠️ Shortened link detected. This could be a phishing attempt."
    return False, "✅ Link appears safe."

# Function to scan a URL using VirusTotal
def scan_url_virustotal(link):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        data = {"url": link}

        # Submit URL to VirusTotal for scanning
        response = requests.post(VIRUSTOTAL_URL_SCAN, headers=headers, data=data)
        
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            return check_url_report_virustotal(analysis_id)
        else:
            return True, f"⚠️ VirusTotal API Error: {response.status_code} - {response.json().get('error', {}).get('message', 'Unknown error')}"
    except Exception as e:
        return True, f"⚠️ Error contacting VirusTotal: {str(e)}"

# Function to check a URL scan report on VirusTotal
def check_url_report_virustotal(analysis_id):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        report_url = VIRUSTOTAL_URL_REPORT.format(analysis_id)

        response = requests.get(report_url, headers=headers)
        
        if response.status_code == 200:
            results = response.json()
            stats = results['data']['attributes']['stats']
            malicious = stats.get('malicious', 0)

            if malicious > 0:
                return True, f"🚨 VirusTotal detected {malicious} malicious reports for this URL!"
            return False, "✅ VirusTotal reports the URL as clean."
        else:
            return True, f"⚠️ Failed to fetch VirusTotal report: {response.status_code}"
    except Exception as e:
        return True, f"⚠️ Error fetching VirusTotal report: {str(e)}"

# Main function to analyze a message
def analyze_message(message):
    print("\nAnalyzing Message...")

    # Extract links using regex
    links = re.findall(r'(https?://\S+)', message)

    # Step 1: Check keywords
    keyword_flag, keyword_message = check_keywords(message)
    print(keyword_message)

    # Step 2: Check links
    short_link_flag = False
    virustotal_flag = False

    if links:
        for link in links:
            # Check for shortened links
            short_link_flag, short_link_message = check_shortened_links(link)
            print(short_link_message)

            # Check with VirusTotal
            virustotal_flag, virustotal_message = scan_url_virustotal(link)
            print(virustotal_message)
    else:
        print("✅ No links detected in the message.")

    # Final verdict
    if keyword_flag or short_link_flag or virustotal_flag:
        print("\n🚨 This message may be a phishing attempt. Proceed with caution!")
    else:
        print("\n✅ Message appears safe.")

# Input a WhatsApp message
message = input("Paste the WhatsApp message here: ")
analyze_message(message)
