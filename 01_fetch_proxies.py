import requests
import base64
import sys

def fetch_proxies():
    """
    Fetches the list of proxy sources, decodes them, and saves the raw proxies to a file.
    """
    url = "https://raw.githubusercontent.com/Arefgh72/v2ray-proxy-pars-tester/main/output/github_all.txt"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an exception for bad status codes

        # The content seems to be base64 encoded, let's decode it.
        try:
            decoded_content = base64.b64decode(response.content)
            # Save the decoded content to a file for the Go program to read
            with open("all_proxies_raw.txt", "w", encoding="utf-8") as f:
                f.write(decoded_content.decode('utf-8', errors='ignore'))
            print("Successfully fetched and saved proxies to all_proxies_raw.txt")
        except (base64.binascii.Error, UnicodeDecodeError) as e:
            print(f"Error decoding content: {e}", file=sys.stderr)
            # If decoding fails, save the raw content for inspection
            with open("all_proxies_raw.txt", "w", encoding="utf-8") as f:
                f.write(response.text)
            print("Decoding failed. Saved raw (undecoded) content for inspection.", file=sys.stderr)
            sys.exit(1)

    except requests.exceptions.RequestException as e:
        print(f"Error fetching proxy sources: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    fetch_proxies()
