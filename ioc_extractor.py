import re


class IOCExtractor:
    """
    Deterministic IOC extraction tool.

    Extracts potential:
    - IPv4 addresses
    - URLs
    - Domains
    - SHA256 hashes
    - SHA1 hashes
    - MD5 hashes

    This tool only extracts indicators that actually appear
    in the supplied investigation case.
    """

    def __init__(self, investigation_case):
        self.case = investigation_case

    def extract_text(self):
        """
        Convert the Investigation Case into searchable text.
        """
        return str(self.case)

    def extract_ips(self, text):
        """
        Extract IPv4 addresses.
        """
        pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

        candidates = re.findall(pattern, text)

        valid_ips = []

        for ip in candidates:
            parts = ip.split(".")

            if all(0 <= int(part) <= 255 for part in parts):
                if ip not in valid_ips:
                    valid_ips.append(ip)

        return valid_ips

    def extract_urls(self, text):
        """
        Extract HTTP/HTTPS URLs.
        """
        pattern = r'https?://[^\s\'"]+'

        urls = re.findall(pattern, text)

        unique_urls = []

        for url in urls:
            if url not in unique_urls:
                unique_urls.append(url)

        return unique_urls

    def extract_domains(self, text):
        """
        Extract domain names.

        URLs are removed first so the domain inside a URL
        is not returned twice.
        """
        text_without_urls = re.sub(
            r'https?://[^\s\'"]+',
            '',
            text
        )

        pattern = (
            r'\b(?:[a-zA-Z0-9-]+\.)+'
            r'[a-zA-Z]{2,}\b'
        )

        domains = re.findall(pattern, text_without_urls)

        unique_domains = []

        for domain in domains:
            domain = domain.lower()

            if domain not in unique_domains:
                unique_domains.append(domain)

        return unique_domains

    def extract_hashes(self, text):
        """
        Extract common file hashes.
        """
        hashes = []

        patterns = {
            "md5": r'\b[a-fA-F0-9]{32}\b',
            "sha1": r'\b[a-fA-F0-9]{40}\b',
            "sha256": r'\b[a-fA-F0-9]{64}\b'
        }

        for hash_type, pattern in patterns.items():

            matches = re.findall(pattern, text)

            for value in matches:

                value = value.lower()

                if value not in [item["value"] for item in hashes]:
                    hashes.append({
                        "type": hash_type,
                        "value": value
                    })

        return hashes

    def extract(self):
        """
        Extract all supported indicators.
        """

        text = self.extract_text()

        ips = self.extract_ips(text)
        urls = self.extract_urls(text)
        domains = self.extract_domains(text)
        hashes = self.extract_hashes(text)

        indicators = []

        for ip in ips:
            indicators.append({
                "type": "ip",
                "value": ip
            })

        for url in urls:
            indicators.append({
                "type": "url",
                "value": url
            })

        for domain in domains:
            indicators.append({
                "type": "domain",
                "value": domain
            })

        indicators.extend(hashes)

        return {
            "indicators": indicators,
            "count": len(indicators)
        }