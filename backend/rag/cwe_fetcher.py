import requests
from bs4 import BeautifulSoup
import logging
import re
from typing import Optional, Dict

logger = logging.getLogger(__name__)

class CWEFetcher:
    """
    Fetches official threat intelligence from the MITRE CWE database.
    """
    BASE_URL = "https://cwe.mitre.org/data/definitions/"

    @classmethod
    def fetch_cwe_details(cls, cwe_id: str) -> Optional[Dict[str, str]]:
        """
        Scrape MITRE CWE page for description, consequences, and mitigations.
        cwe_id format expected: "CWE-89"
        """
        # Extract just the number (e.g. "CWE-89" -> "89")
        match = re.search(r'\d+', cwe_id)
        if not match:
            logger.error(f"Invalid CWE ID format: {cwe_id}")
            return None
            
        cwe_num = match.group(0)
        url = f"{cls.BASE_URL}{cwe_num}.html"
        
        try:
            logger.info(f"Fetching online threat intelligence from: {url}")
            # Use a standard user-agent so MITRE doesn't block the request
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code != 200:
                logger.warning(f"Failed to fetch {cwe_id} from MITRE. HTTP {response.status_code}")
                return None
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract Title
            title_tag = soup.find('h2')
            title = title_tag.text.strip() if title_tag else cwe_id
            
            # Extract Description
            desc_div = soup.find('div', id='Description')
            description = ""
            if desc_div:
                desc_detail = desc_div.find('div', class_='detail')
                description = desc_detail.text.strip() if desc_detail else ""
                
            # Extract Mitigations / Potential Mitigations
            mitigations_div = soup.find('div', id='Potential_Mitigations')
            mitigations_text = ""
            if mitigations_div:
                mitigations_detail = mitigations_div.find('div', class_='detail')
                mitigations_text = mitigations_detail.text.strip() if mitigations_detail else ""
            
            # Clean up excessive newlines
            description = re.sub(r'\n+', '\n', description)
            mitigations_text = re.sub(r'\n+', '\n', mitigations_text)
            
            combined_context = f"{title}\n\nDescription:\n{description}\n\nMitigations:\n{mitigations_text}"
            
            if not description and not mitigations_text:
                return None
                
            return {
                "cwe_id": cwe_id,
                "title": title,
                "context": combined_context
            }
            
        except Exception as e:
            logger.error(f"Error fetching {cwe_id} from MITRE: {str(e)}")
            return None

# Simple manual test if run directly
if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO)
    data = CWEFetcher.fetch_cwe_details("CWE-89")
    print(json.dumps(data, indent=2))
