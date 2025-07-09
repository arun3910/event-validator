from seleniumwire import webdriver
from selenium.webdriver.chrome.options import Options
import json

class BrowserSession:
    def __init__(self, headless=False):
        chrome_options = Options()
        if headless:
            chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--window-size=1080,800")
        chrome_options.add_argument("--window-position=10,10")
        self.driver = webdriver.Chrome(options=chrome_options)

        self.matched_request = None  # Store matched request for real-time viewer
        self.match_url_filter = None  # Pattern to match
        self.match_type = 'exact'     # Can be 'exact', 'regex', or 'glob'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.driver.quit()

    def visit(self, url):
        self.driver.get(url)
        self.driver.requests.clear()
        self.matched_request = None  # Reset

    def set_request_matcher(self, url_filter, match_type):
        self.match_url_filter = url_filter
        self.match_type = match_type

    def matches(self, url):
        import re
        from fnmatch import fnmatch

        if self.match_type == 'regex':
            return re.match(self.match_url_filter, url)
        elif self.match_type == 'glob':
            return fnmatch(url, self.match_url_filter)
        return url == self.match_url_filter

    def get_all_event_payloads(self):
        results = []

        for request in self.driver.requests:
            if request.method != 'POST':
                continue

            try:
                body = request.body.decode('utf-8')
                parsed = json.loads(body)

                # Match this request to store for real-time display
                if self.match_url_filter and self.matches(request.url) and self.matched_request is None:
                    self.matched_request = {
                        'url': request.url,
                        'method': request.method,
                        'headers': dict(request.headers),
                        'payload': parsed,
                        'status': request.response.status_code if request.response else 'N/A'
                    }

                for event in parsed.get('events', []):
                    results.append((
                        event.get("name"),
                        event,
                        {
                            **parsed,
                            "url": request.url
                        }
                    ))
            except Exception:
                continue

        return results

    def get_matched_request_details(self):
        return self.matched_request
