import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Requester:
    def __init__ (self):
        self.session = requests.Session()

        self.session.headers.update ({
            "User-Agent": "WebScanner/1.0"
        })

    """
    
    def get(self, url, params=None):
        try:
            response = self.session.get(
                url=url,
                params=params,
                timeout=10,
                verify=False
            )
            return response

        except Exception as e:
            print(f"The Response Error: {e}")
            return None
            
    """
    
    def get(self, url, params=None):
        try:
            for _ in range(2):
                response = self.session.get(
                    url,
                    params=params,
                    timeout=10,
                    verify=False
                )

                if response.status_code in [200, 500, 403]:
                    return response

            return None

        except:
            return None
        

    def post (self, url, data):
        try:
            response = self.session.post(url=url, data=data, timeout=10, verify=False)

            return response
        
        except Exception as post_request_error:
            
            print(f"The Post Request Error: {post_request_error}")
            return None