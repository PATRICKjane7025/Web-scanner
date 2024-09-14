from flask import Flask, render_template, request
import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import time

app = Flask(__name__)


CHROME_DRIVER_PATH = '"C:/Users/aravi/Downloads/chromedriver-win64/chromedriver.exe"'  

def init_webdriver():
    chrome_options = Options()
    chrome_options.add_argument("--headless")  
    service = ChromeService(executable_path=CHROME_DRIVER_PATH)
    driver = webdriver.Chrome(service=service, options=chrome_options)
    return driver

def check_server_software(url):
    try:
        response = requests.get(url)
        headers = response.headers
        return {
            'Server Software': headers.get('Server', 'Not found'),
            'X-Powered-By': headers.get('X-Powered-By', 'Not found')
        }
    except requests.RequestException as e:
        return {'Error': str(e)}

def check_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        required_headers = [
            'Referrer-Policy',
            'Content-Security-Policy',
            'X-Content-Type-Options'
        ]
        missing_headers = [header for header in required_headers if header not in headers]
        return {
            'Missing Security Headers': ', '.join(missing_headers) if missing_headers else 'All required headers are present.'
        }
    except requests.RequestException as e:
        return {'Error': str(e)}

def check_directory_listing(url):
    try:
        response = requests.get(url)
        return {'Directory Listing': 'Enabled' if 'Index of' in response.text else 'Not Enabled'}
    except requests.RequestException as e:
        return {'Error': str(e)}

def check_client_access_policy(url):
    try:
        response = requests.get(url)
        return {
            'Client Access Policy': 'Secure' if 'X-Content-Type-Options' in response.headers else 'Insecure'
        }
    except requests.RequestException as e:
        return {'Error': str(e)}

def check_cookie_security(url):
    try:
        response = requests.get(url)
        cookies = response.cookies
        cookie_info = []
        for cookie in cookies:
            cookie_info.append({
                'Cookie': cookie.name,
                'Secure': cookie.secure,
                'HttpOnly': cookie.has_nonstandard_attr('HttpOnly')
            })
        return {'Cookies': cookie_info}
    except requests.RequestException as e:
        return {'Error': str(e)}

def test_xss(url):
    driver = init_webdriver()
    try:
        driver.get(url)
        xss_payload = "<script>alert('XSS');</script>"
        input_element = driver.find_element(By.NAME, 'search')  
        input_element.send_keys(xss_payload + Keys.RETURN)
        time.sleep(5)
        alert_present = False
        try:
            alert = driver.switch_to.alert
            alert_present = True
            alert.dismiss()
        except:
            pass
        return {'XSS Vulnerability': 'Detected' if alert_present else 'Not Detected'}
    except Exception as e:
        return {'Error': str(e)}
    finally:
        driver.quit()

def test_sql_injection(url):
    try:
        payload = "' OR '1'='1"
        test_url = f"{url}?id={payload}"
        response = requests.get(test_url)
        if 'SQL syntax' in response.text or 'mysql' in response.text.lower():
            return {'SQL Injection Vulnerability': 'Detected'}
        else:
            return {'SQL Injection Vulnerability': 'Not Detected'}
    except requests.RequestException as e:
        return {'Error': str(e)}

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        target_url = request.form['url']
        results = {
            'Server Software': check_server_software(target_url),
            'Security Headers': check_security_headers(target_url),
            'Directory Listing': check_directory_listing(target_url),
            'Client Access Policy': check_client_access_policy(target_url),
            'Cookie Security': check_cookie_security(target_url),
            'XSS Testing': test_xss(target_url),
            'SQL Injection Testing': test_sql_injection(target_url)
        }
        return render_template('result.html', results=results, url=target_url)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
