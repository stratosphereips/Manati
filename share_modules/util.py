import json
from constants import Constant
import re
import socket
from urlparse import urlparse
from tld import get_tld


class ComplexEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'reprJSON'):
            return obj.reprJSON()
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        else:
            return json.JSONEncoder.default(self, obj)


def convert_obj_to_json(obj):
    return json.dumps(obj,cls=ComplexEncoder)


def get_domain_by_obj(attributes_obj):
    keys = attributes_obj.keys()
    possible_key_url = Constant.URL_ATTRIBUTES_AVAILABLE
    indices = [i for (i, x) in enumerate(keys) if x in set(keys).intersection(possible_key_url)]
    if indices:
        key_url = str(keys[indices[0]])
        if key_url == 'host':
            return str(attributes_obj[key_url])
        else:
            return get_domain(str(attributes_obj[key_url]))
    else:
        return None


def is_ip(value):
    """Determine if a value is an IP address.

    :param str value: Value to check
    :return: Boolean status outling if the value is an IP address
    """
    try:
        socket.inet_aton(value)
        return True
    except socket.error:
        return False


def get_data_from_url(url):
    if is_ip(url):
        return 'ip', url
    o = urlparse(url)
    d = o.netloc
    if d is None or d == '':
        return 'domain','none'
    elif is_ip(d):
        return 'ip', d
    else:
        return 'domain', get_tld('http://www.'+d)



def get_domain(url):
    """Return top two domain levels from URI"""
    re_3986_enhanced = re.compile(r"""
        # Parse and capture RFC-3986 Generic URI components.
        ^                                    # anchor to beginning of string
        (?:  (?P<scheme>    [^:/?#\s]+): )?  # capture optional scheme
        (?://(?P<authority>  [^/?#\s]*)  )?  # capture optional authority
             (?P<path>        [^?#\s]*)      # capture required path
        (?:\?(?P<query>        [^#\s]*)  )?  # capture optional query
        (?:\#(?P<fragment>      [^\s]*)  )?  # capture optional fragment
        $                                    # anchor to end of string
        """, re.MULTILINE | re.VERBOSE)
    re_domain = re.compile(r"""
        # Pick out top two levels of DNS domain from authority.
        (?P<domain>[^.]+\.[A-Za-z]{2,6})  # $domain: top two domain levels.
        (?::[0-9]*)?                      # Optional port number.
        $                                 # Anchor to end of string.
        """,
                           re.MULTILINE | re.VERBOSE)
    result = ""
    m_uri = re_3986_enhanced.match(url)
    if m_uri and m_uri.group("authority"):
        auth = m_uri.group("authority")
        m_domain = re_domain.search(auth)
        if m_domain and m_domain.group("domain"):
            result = m_domain.group("domain")
    return result