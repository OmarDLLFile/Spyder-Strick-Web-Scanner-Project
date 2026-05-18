from bs4 import BeautifulSoup

class FormParser:

    @staticmethod
    def extract_forms(html):

        if not html:
            return []

        soup = BeautifulSoup(html, "lxml")

        forms_data = []

        forms = soup.find_all("form")

        for form in forms:

            form_details = {}

            form_details["action"] = form.attrs.get("action", "")
            form_details["method"] = form.attrs.get("method", "get")

            inputs = []

            for input_tag in form.find_all("input"):

                inputs.append({
                    "type": input_tag.attrs.get("type", "text"),
                    "name": input_tag.attrs.get("name")
                })

            form_details["inputs"] = inputs

            forms_data.append(form_details)

        return forms_data
            
            
        # The Parser Output Format
        
        """
            
    [
        {
            "action": "/login",
            "method": "post",
            "inputs": [
                
                {
                    "type": "text",
                    "name": "username"
                }
            ]
        }
    ]
            
            """

