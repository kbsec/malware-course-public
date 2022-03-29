import sys
import requests 

def make_request(fqdn, port, uri, use_tls):
    transport = "http" if use_tls == "0" else "https"
    url = f"{transport}://{fqdn}:{port}{uri}"
    print(f"DEBUG: {url}")
    r = requests.get(url )
    if r.status_code == 200:
        print(r.text)
        return 


def main():
    if len(sys.argv) != 5:
        print(f"Example Useage: {sys.argv[0]} google.com 443 / 1")
        return 
    fqdn, port, uri, use_tls = sys.argv[1:]
    print(make_request(fqdn, port, uri, use_tls))

if __name__ == "__main__":
    main()