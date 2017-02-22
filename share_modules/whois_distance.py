import Levenshtein
from share_modules.util import convert_obj_to_json
import dateutil.parser
import datetime
import json
import whois
from manati_ui.models import WhoisConsult

KEY_DOMAIN_NAME = 'domain_name'
KEY_REGISTRAR = 'registrar'
KEY_NAME = 'name'
KEY_ORG = 'org'
KEY_ZIPCODE = 'zipcode'
KEY_CREATION_DATE = 'creation_date'
KEY_EXPIRATION_DATE = 'expiration_date'
KEY_EMAILS = 'emails'

weights = [0,1,1,1,1,1,1]


class WhoisObj:

    def __init__(self, domain):
        self.domain = domain
        self.result = WhoisConsult.get_query_by_domain(domain)

    @staticmethod
    def make_whois_domain(domain):
        try:
            return whois.whois(domain)
        except Exception as e:
            # print(e)
            print(domain, " is not in DB")
            return None

    def get_result_struc(self):
        if self.result:
            result = json.loads(self.result)
        else:
            result = {}
        return result

    def get_results_struc_filtered(self):
        result = self.get_result_struc()
        result['domain_name'] = self.get_domains_name()[0] if self.get_domains_name() else ''
        result[KEY_EXPIRATION_DATE] = self.get_str_expiration_date()
        result[KEY_CREATION_DATE] = self.get_str_creation_date()
        result['emails'] = self.get_str_emails()
        return result

    def get_domains_name(self):
        result = self.get_result_struc()
        domain_names = result.get('domain_name', [])
        domain_names = domain_names if domain_names else []
        domain_names = [dn.lower() for dn in domain_names]
        return domain_names

    # time to live in days
    def get_ttl_days(self):
        cd = self.get_creation_date()
        ed = self.get_expiration_date()
        if cd and ed:
            return abs(cd - ed).days
        else:
            return None

    def get_creation_date(self):
        result = self.get_result_struc()
        cd = None
        if KEY_CREATION_DATE in result:
            creation = result[KEY_CREATION_DATE]
            if type(creation) is list:
                cd = creation[1]
            elif not creation:
                return None
            elif 'before' in creation:
                cd = creation.split(' ')[1]
            elif creation:
                cd = creation

            if cd:
                return dateutil.parser.parse(cd[0:19])
            else:
                return None
        else:
            return None

    def get_expiration_date(self):
        result = self.get_result_struc()
        ed = None
        if KEY_EXPIRATION_DATE in result:
            expiration = result[KEY_EXPIRATION_DATE]
            if type(expiration) is list:
                ed = expiration[1]
            elif expiration and not expiration == 'not defined':
                ed = expiration
            elif not expiration or expiration == 'not defined':
                return None

            if ed:
                return dateutil.parser.parse(ed[0:19])
            else:
                return None
        else:
            return None

    def get_str_emails(self):
        return ",".join([str(email) for email in self.get_emails()])

    def get_emails(self):
        result = self.get_result_struc()
        emails = result.get('emails', None)
        if emails:
            if isinstance(emails, list):
                return emails
            else:
                return [emails]
        else:
            return []


    def get_str_creation_date(self, format='%d-%m-%Y'):
        date = self.get_creation_date()
        if date:
            return date.strftime(format)
        else:
            return ''

    def get_str_expiration_date(self, format='%d-%m-%Y'):
        date = self.get_expiration_date()
        if date:
            return date.strftime(format)
        else:
            return ''


def dot(v1, v2):
    return sum(x*y for x,y in zip(v1,v2))


def init_keys(domain_name, registrar, name, org, zipcode, creation_date, expiration_date, emails):
    global KEY_DOMAIN_NAME, KEY_REGISTRAR, KEY_NAME, KEY_ORG, KEY_ZIPCODE, KEY_CREATION_DATE,\
        KEY_EXPIRATION_DATE, KEY_EMAILS

    KEY_DOMAIN_NAME = domain_name
    KEY_REGISTRAR = registrar
    KEY_NAME = name
    KEY_ORG = org
    KEY_ZIPCODE = zipcode
    KEY_CREATION_DATE = creation_date
    KEY_EXPIRATION_DATE = expiration_date
    KEY_EMAILS = emails


def __dist_domain__name__(domain_name_a, domain_name_b):
    return Levenshtein.distance(str(domain_name_a).lower(), str(domain_name_b).lower())


def __dist_registrar__(registrar_a, registrar_b):
    return Levenshtein.distance(str(registrar_a).lower(), str(registrar_b).lower())


def __dist_name__(name_a, name_b):
    return Levenshtein.distance(str(name_a).lower(), str(name_b).lower())


def __dist_org__(org_a, org_b):
    return Levenshtein.distance(str(org_a).lower(), str(org_b).lower())


def __dist_zipcode__(zipcode_a, zipcode_b):
    return Levenshtein.distance(str(zipcode_a).lower(), str(zipcode_b).lower())


# ttl by proportion, more close tu cero, more close is the ttl
def get_diff_ttl(creation_date_a, creation_date_b,expiration_date_a, expiration_date_b):
    if not creation_date_a  and not creation_date_b  and expiration_date_a and not expiration_date_a:
        return float(0)
    elif not creation_date_a and not creation_date_b and expiration_date_a and expiration_date_a:
        if expiration_date_a == expiration_date_a:
            return float(0)
        else:
            return float(1)
    elif creation_date_a and creation_date_b and not expiration_date_a and not expiration_date_a:
        if creation_date_a == creation_date_a:
            return float(0)
        else:
            return float(1)
    elif not creation_date_a or not creation_date_b or not expiration_date_a  or not expiration_date_a:
        return float(1)
    else:
        cd_a = datetime.datetime.strptime(creation_date_a, '%d-%m-%Y')
        ed_a = datetime.datetime.strptime(expiration_date_a, '%d-%m-%Y')
        cd_b = datetime.datetime.strptime(creation_date_b, '%d-%m-%Y')
        ed_b = datetime.datetime.strptime(expiration_date_b, '%d-%m-%Y')
        ttl_days_b = float(abs(cd_b - ed_b).days)  # time to live
        ttl_days_a = float(abs(cd_a - ed_a).days)
        return float(1) - ((ttl_days_b / ttl_days_a) if ttl_days_b <= ttl_days_a else (ttl_days_a / ttl_days_b))


# Method computing distance where emails are measured with "taking the minimun distance techniques "
def get_diff_emails_by_min_dist(emails_str_a, emails_str_b):
    emails_seed = emails_str_a.split(',')
    emails_file = emails_str_b.split(',')
    dist_email = Levenshtein.distance(str(emails_seed[0]), str(emails_file[0]))
    for email_s in emails_seed:
        for email_f in emails_file:
            dist_email = min(str(dist_email), str(Levenshtein.distance(str(email_s), email_f)))
    return float(dist_email)


def features_domains_attr(domain_name_a, registrar_a, name_a, org_a, zipcode_a, creation_date_a,
                         expiration_date_a, emails_str_a,
                         domain_name_b, registrar_b, name_b, org_b, zipcode_b, creation_date_b,
                         expiration_date_b, emails_str_b):
    dist_domain_name = __dist_domain__name__(domain_name_a, domain_name_b)
    dist_registrar = __dist_registrar__(registrar_a, registrar_b)
    dist_name = __dist_name__(name_a, name_b)
    dist_org = __dist_org__(org_a, org_b)
    dist_zipcode = __dist_zipcode__(zipcode_a, zipcode_b)
    diff_ttl = get_diff_ttl(creation_date_a, creation_date_b,expiration_date_a, expiration_date_b)
    diff_emails = get_diff_emails_by_min_dist(emails_str_a, emails_str_b)
    return [dist_domain_name, dist_registrar, dist_name, dist_org,
            dist_zipcode, round(diff_ttl, 2), round(diff_emails, 2)]


def features_domains(whois_info_a={}, whois_info_b={}):
    domain_name_a = whois_info_a.get( KEY_DOMAIN_NAME,'')
    registrar_a = whois_info_a.get(KEY_REGISTRAR,'')
    name_a = whois_info_a.get(KEY_NAME,'')
    org_a = whois_info_a.get(KEY_ORG,'')
    zipcode_a = whois_info_a.get(KEY_ZIPCODE,'')
    creation_date_a = whois_info_a.get(KEY_CREATION_DATE,'')
    expiration_date_a = whois_info_a.get(KEY_EXPIRATION_DATE,'')
    emails_str_a = whois_info_a.get(KEY_EMAILS, '')

    domain_name_b = whois_info_b.get(KEY_DOMAIN_NAME, '')
    registrar_b = whois_info_b.get(KEY_REGISTRAR, '')
    name_b = whois_info_b.get(KEY_NAME, '')
    org_b = whois_info_b.get(KEY_ORG, '')
    zipcode_b = whois_info_b.get(KEY_ZIPCODE, '')
    creation_date_b = whois_info_b.get(KEY_CREATION_DATE, '')
    expiration_date_b = whois_info_b.get(KEY_EXPIRATION_DATE, '')
    emails_str_b = whois_info_b.get(KEY_EMAILS, '')

    return features_domains_attr(domain_name_a, registrar_a, name_a, org_a, zipcode_a, creation_date_a,
                         expiration_date_a, emails_str_a,
                         domain_name_b, registrar_b, name_b, org_b, zipcode_b, creation_date_b,
                         expiration_date_b, emails_str_b)


def distance_obj(whois_info_a, whois_info_b):
    feature_values = features_domains(whois_info_a, whois_info_b)
    # multiply = list(np.multiply(feature_values, weights))
    # sum_features = sum(multiply)
    sum_features = dot(feature_values,weights)
    return abs(sum_features)


def distance_domains(domain_a, domain_b):
    whois_info_a = WhoisObj(domain_a).get_results_struc_filtered()
    whois_info_b = WhoisObj(domain_b).get_results_struc_filtered()
    return distance_obj(whois_info_a, whois_info_b)

