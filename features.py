import re
from urllib.parse import urlparse

def extract_features(url: str) -> dict:
    url = url.strip().rstrip('/')
    parsed = urlparse(url if '://' in url else 'http://' + url)
    host = parsed.netloc.lower().split(':')[0]
    host_nowww = host[4:] if host.startswith('www.') else host
    parts = host_nowww.split('.')
    tld = parts[-1] if len(parts) > 1 else ''

    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    other_special = len(re.findall(r'[^A-Za-z0-9=?&./:\-]', url))
    n = max(len(url), 1)

    return {
        'URLLength': len(url),
        'DomainLength': len(host),
        'IsDomainIP': int(bool(re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host))),
        'TLD': tld,
        'TLDLength': len(tld),
        'NoOfSubDomain': max(len(parts) - 2, 0),
        'IsHTTPS': int(parsed.scheme == 'https'),
        'HasWWW': int(host.startswith('www.')),
        'NoOfDots': url.count('.'),
        'NoOfLetters': letters,
        'NoOfDigits': digits,
        'LetterRatio': letters / n,
        'DigitRatio': digits / n,
        'NoOfEquals': url.count('='),
        'NoOfQMark': url.count('?'),
        'NoOfAmpersand': url.count('&'),
        'NoOfHyphenInDomain': host.count('-'),
        'HasAtSymbol': int('@' in url),
        'NoOfPercentEncoded': len(re.findall(r'%[0-9a-fA-F]{2}', url)),
        'NoOfOtherSpecial': other_special,
        'SpecialRatio': other_special / n,
        'PathLength': len(parsed.path),
        'PathDepth': parsed.path.count('/'),
    }
