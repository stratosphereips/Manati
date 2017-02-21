import Levenshtein
import datetime

KEY_DOMAIN_NAME = 'domain_name'
KEY_REGISTRAR = 'registrar'
KEY_NAME = 'name'
KEY_ORG = 'org'
KEY_ZIPCODE = 'zipcode'
KEY_CREATION_DATE = 'creation_date'
KEY_EXPIRATION_DATE = 'expiration_date'
KEY_EMAILS = 'emails'

weights = [0,1,1,1,1,1,1]


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


def distance_domains(whois_info_a, whois_info_b):
    feature_values = features_domains(whois_info_a, whois_info_b)
    # multiply = list(np.multiply(feature_values, weights))
    # sum_features = sum(multiply)
    sum_features = dot(feature_values,weights)
    return abs(sum_features)

