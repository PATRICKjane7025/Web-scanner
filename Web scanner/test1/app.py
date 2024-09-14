from flask import Flask, request, render_template
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from tags import tags
from sqltags import sqltags

app = Flask(__name__)

SCAN_URL = "https://www.example.com"


def detect_server_software(response):
    server_software = response.headers.get("Server")
    return server_software if server_software else None


def detect_directory_listing(response):
    return response.status_code == 200 and "Index of" in response.text


def detect_insecure_client_access_policy(response):
    return "access-control-allow-origin" not in response.headers


def detect_missing_security_headers(response):
    missing_headers = []
    required_headers = [
        "Referrer-Policy",
        "Content-Security-Policy",
        "X-Content-Type-Options"
    ]
    for header in required_headers:
        if header not in response.headers:
            missing_headers.append(header)
    return missing_headers


def detect_unsafe_http_header_csp(response):
    csp_header = response.headers.get("Content-Security-Policy")
    return csp_header and "unsafe-inline" in csp_header


def detect_secure_cookie(response):
    cookies = response.cookies
    for cookie in cookies:
        if not cookie.secure:
            return False
    return True


def detect_httponly_cookie(response):
    cookies = response.cookies
    for cookie in cookies:
        if not cookie.has_nonstandard_attr("HttpOnly"):
            return False
    return True


def detect_security_txt(url):
    security_txt_url = f"{url}/.well-known/security.txt"
    try:
        response = requests.get(security_txt_url)
        if response.status_code == 200:
            return response.text
    except requests.RequestException:
        return None


def xss_testing(url):
    options = Options()
    options.headless = True
    driver = webdriver.Chrome(options=options)
    driver.get(url)
    
    xss_vulnerable = False

    # Loop through XSS payloads
    for payload in tags:
        try:
            # Inject the payload into the page using JavaScript
            driver.execute_script(f"document.body.innerHTML = '{payload}'")
            xss_vulnerable = True
            break  # Stop if a vulnerability is found
        except Exception as e:
            print(f"Error during XSS testing with payload {payload}: {e}")

    driver.quit()
    return xss_vulnerable


def sql_injection_testing(url):
    vulnerable = False
    for payload in sqltags:
        try:
            test_url = f"{url}{payload}"
            response = requests.get(test_url)

            # A delay in response time could indicate a SQL Injection vulnerability
            if response.elapsed.total_seconds() > 20:
                print(f"Potential SQL Injection vulnerability found with payload: {payload}")
                vulnerable = True
                break
        except requests.exceptions.RequestException as e:
            print(f"Request failed with payload {payload}: {e}")
    return vulnerable


def scan_website():
    vulnerabilities = []
    try:
        response = requests.get(SCAN_URL)
        
        # Detect server software
        server_software = detect_server_software(response)
        if server_software:
            vulnerabilities.append(f"Server software: {server_software}")

        # Detect directory listing
        if detect_directory_listing(response):
            vulnerabilities.append("Directory listing is enabled")

        # Detect insecure client access policy
        if detect_insecure_client_access_policy(response):
            vulnerabilities.append("Insecure client access policy")

        # Detect missing security headers
        missing_headers = detect_missing_security_headers(response)
        if missing_headers:
            vulnerabilities.append(f"Missing security headers: {', '.join(missing_headers)}")

        # Detect unsafe HTTP header CSP
        if detect_unsafe_http_header_csp(response):
            vulnerabilities.append("Unsafe HTTP header Content Security Policy")

        # Detect secure cookie
        if not detect_secure_cookie(response):
            vulnerabilities.append("Secure flag of cookie is not set")

        # Detect HttpOnly cookie
        if not detect_httponly_cookie(response):
            vulnerabilities.append("HttpOnly flag of cookie is not set")

        # Detect security.txt
        security_txt = detect_security_txt(SCAN_URL)
        if security_txt:
            vulnerabilities.append(f"Security.txt: {security_txt}")

        # XSS testing
        if xss_testing(SCAN_URL):
            vulnerabilities.append("XSS vulnerability found")

        # SQL Injection testing
        if sql_injection_testing(SCAN_URL):
            vulnerabilities.append("SQL injection vulnerability found")

    except requests.RequestException as e:
        vulnerabilities.append(f"An error occurred while scanning: {e}")

    return vulnerabilities


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["GET"])
def scan():
    vulnerabilities = scan_website()
    return render_template("result.html", vulnerabilities=vulnerabilities)


if __name__ == "__main__":
    app.run(debug=True)


#improve UI 
#button for new scan 
#imorove description 

