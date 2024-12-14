import re
import requests

# Common phishing keywords
PHISHING_KEYWORDS = [
    "urgent", "verify your account", "click here", "prize", "payment", "congratulations", "lottery", "refund", "password reset"
]

# Function to check suspicious keywords in messages
def check_keywords(message):
    for keyword in PHISHING_KEYWORDS:
        if keyword in message.lower():
            return True, f"⚠️ Suspicious keyword detected: '{keyword}'"
    return False, "✅ No suspicious keywords found."

# Function to check if a link is shortened (common in phishing)
def check_shortened_links(link):
    if re.match(r"(https?://)?(bit\.ly|tinyurl\.com|t\.co|goo\.gl|short\.io)", link):
        return True, "⚠️ Shortened link detected. This could be a phishing attempt."
    return False, "✅ Link appears safe."

# Function to validate links (optional: check against PhishTank or other services)
def validate_link(link):
    try:
        response = requests.get(link, timeout=5)
        if response.status_code != 200:
            return True, "⚠️ Link may be broken or unsafe."
        return False, "✅ Link is active and responding."
    except:
        return True, "⚠️ Failed to access link. It might be unsafe."

# Main function to analyze a message
def analyze_message(message):
    print("\nAnalyzing Message...")

    # Extract links using regex
    links = re.findall(r'(https?://\S+)', message)

    # Initialize flags to avoid reference errors
    keyword_flag = False
    short_link_flag = False
    broken_link_flag = False

    # Step 1: Check keywords
    keyword_flag, keyword_message = check_keywords(message)
    print(keyword_message)

    # Step 2: Check links
    if links:
        for link in links:
            short_link_flag, short_link_message = check_shortened_links(link)
            print(short_link_message)

            # Validate link
            broken_link_flag, link_validation_message = validate_link(link)
            print(link_validation_message)
    else:
        print("✅ No links detected in the message.")

    # Final verdict
    if keyword_flag or short_link_flag or broken_link_flag:
        print("\n🚨 This message may be a phishing attempt. Proceed with caution!")
    else:
        print("\n✅ Message appears safe.")


# Input a WhatsApp message
message = input("Paste the WhatsApp message here: ")
analyze_message(message)

