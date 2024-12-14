# WhatsApp Phishing Detector 🚨

A simple tool built with Python to analyze WhatsApp messages for phishing attempts. It detects suspicious keywords, shortened links, and broken or unsafe URLs to help protect users, especially vulnerable groups like the elderly, from phishing scams.

---

## Features 🛡️
- **Suspicious Keywords Detection**: Identifies common phishing terms like "urgent," "click here," or "account suspended."  
- **Shortened Link Detection**: Recognizes links from common URL shorteners like `bit.ly` and `tinyurl` which are often used in phishing attempts.  
- **Link Validation**: Checks the safety of links by attempting to reach them and identifying broken or malicious links.  
- **Clear Feedback**: Provides a clear, user-friendly analysis of the message.

---

## How It Works ⚙️
1. **Input a WhatsApp Message**: Paste the message you'd like to analyze into the terminal.  
2. **Message Analysis**: The script checks for suspicious keywords, shortened links, and unreachable/broken URLs.  
3. **Feedback**: A report is generated indicating whether the message is safe or suspicious.  

---

## Installation 🛠️
To run the project on your machine:  

1. **Clone the repository**:  
   ```bash
   git clone https://github.com/your-username/whatsapp-phishing-detector.git
   cd whatsapp-phishing-detector
   ```

2. **Set up the environment**:  
   Ensure Python 3 is installed, and install required libraries:  
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the script**:  
   ```bash
   python3 Main.py
   ```

---

## Example Output 💻
```bash
Paste the WhatsApp message here: Your account has been suspended! Click here: https://bit.ly/xyz

Analyzing Message...
🚨 Suspicious keywords found: "suspended"
⚠️ Shortened link detected: https://bit.ly/xyz
🚨 Unable to verify the link. It might be broken or malicious.

🚨 This message may be a phishing attempt. Proceed with caution!
```

---

## Future Improvements 🚀
- Add integration with external APIs for link safety checks (e.g., VirusTotal).  
- Expand the database of suspicious keywords.  
- Create a GUI version for better accessibility.  
