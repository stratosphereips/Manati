import Levenshtein
import numpy as np
from sklearn.metrics import r2_score
from sklearn.utils.extmath import safe_sparse_dot
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
KEY_NAME_SERVERS = 'name_servers'

weights = [0,1,1,1,1,1,1,1]


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


def __levenshtein__(str1,str2):
    str1 = str1.encode('utf-8')
    str2 = str2.encode('utf-8')
    return Levenshtein.distance(str1.lower(),str2.lower())

def __dist_domain__name__(domain_name_a, domain_name_b):
    return __levenshtein__(str(domain_name_a).lower(), str(domain_name_b).lower())


def __dist_registrar__(registrar_a, registrar_b):
    registrar_a = registrar_a[0] if isinstance(registrar_a, list) else registrar_a
    registrar_b = registrar_b[0] if isinstance(registrar_b, list) else registrar_b
    registrar_a = registrar_a if not registrar_a is None else ''
    registrar_b = registrar_b if not registrar_b is None else ''
    registrar_a = registrar_a.encode('utf-8')
    registrar_b = registrar_b.encode('utf-8')
    return __levenshtein__(str(registrar_a).lower(), str(registrar_b).lower())


def __dist_name__(name_a, name_b):
    return __levenshtein__(str(name_a).lower(), str(name_b).lower())


def __dist_org_by_min_dist__(orgs_a=[], orgs_b=[]):
    orgs_seed = orgs_a.split(',') if not isinstance(orgs_a, list) else orgs_a
    orgs_file = orgs_b.split(',') if not isinstance(orgs_b, list) else orgs_b
    if not orgs_seed and not orgs_file:
        return float(0)
    elif not orgs_seed:
        orgs_seed = ['']
    elif not orgs_file:
        orgs_file = ['']

    dist_org = __levenshtein__(str(orgs_seed[0]), str(orgs_file[0]))
    for org_s in orgs_seed:
        org_s = org_s.encode('utf-8')
        for org_f in orgs_file:
            org_f = org_f.encode('utf-8')
            dist_org = min(str(dist_org), str(__levenshtein__(str(org_s), str(org_f))))
    return float(dist_org)


def __dist_zipcode_by_min_dist__(zipcodes_a=[], zipcodes_b=[]):
    zipcodes_seed = zipcodes_a.split(',') if not isinstance(zipcodes_a, list) else zipcodes_a
    zipcodes_file = zipcodes_b.split(',') if not isinstance(zipcodes_b, list) else zipcodes_b
    if not zipcodes_seed and not zipcodes_file:
        return float(0)
    elif not zipcodes_seed:
        zipcodes_seed = ['']
    elif not zipcodes_file:
        zipcodes_file = ['']
    dist_zipcode = __levenshtein__(str(zipcodes_seed[0]), str(zipcodes_file[0]))
    for zipcode_s in zipcodes_seed:
        for zipcode_f in zipcodes_file:
            dist_zipcode = min(str(dist_zipcode), str(__levenshtein__(str(zipcode_s), str(zipcode_f))))
    return float(dist_zipcode)


# ttl by proportion, more close tu cero, more close is the ttl
def get_diff_ttl(creation_date_a, creation_date_b,expiration_date_a, expiration_date_b):
    if not creation_date_a and not creation_date_b and not expiration_date_a and not expiration_date_a:
        return float(0)
    elif not creation_date_a and not creation_date_b and expiration_date_a and expiration_date_b:
        if expiration_date_a == expiration_date_a:
            return float(0)
        else:
            return float(1)
    elif creation_date_a and creation_date_b and not expiration_date_a and not expiration_date_b:
        if creation_date_a == creation_date_a:
            return float(0)
        else:
            return float(1)
    elif not creation_date_a or not creation_date_b or not expiration_date_a or not expiration_date_b:
        return float(1)
    else:
        try:
            cd_a = datetime.datetime.strptime(creation_date_a, '%d-%m-%Y') if not isinstance(creation_date_a, datetime.datetime) else creation_date_a
            ed_a = datetime.datetime.strptime(expiration_date_a, '%d-%m-%Y') if not isinstance(expiration_date_a, datetime.datetime) else creation_date_a
            cd_b = datetime.datetime.strptime(creation_date_b, '%d-%m-%Y') if not isinstance(creation_date_b, datetime.datetime) else creation_date_a
            ed_b = datetime.datetime.strptime(expiration_date_b, '%d-%m-%Y') if not isinstance(expiration_date_b, datetime.datetime) else creation_date_a
        except Exception as e:
            cd_a = dateutil.parser.parse(creation_date_a)
            ed_a = dateutil.parser.parse(expiration_date_a)
            cd_b = dateutil.parser.parse(creation_date_b)
            ed_b = dateutil.parser.parse(expiration_date_b)

        ttl_days_b = float(abs(cd_b - ed_b).days)  # time to live
        ttl_days_a = float(abs(cd_a - ed_a).days)
        if ttl_days_b == ttl_days_b:
            return float(0)
        else:
            return float(1) - ((ttl_days_b / ttl_days_a) if ttl_days_b <= ttl_days_a else (ttl_days_a / ttl_days_b))


# Method computing distance where emails are measured with "taking the minimun distance techniques "
def get_diff_emails_by_min_dist(emails_a=[], emails_b=[]):
    emails_seed = emails_a.split(',') if not isinstance(emails_a, list) else emails_a
    emails_file = emails_b.split(',') if not isinstance(emails_b, list) else emails_b
    if not emails_seed and not emails_file:
        return float(0)
    elif not emails_seed:
        emails_seed = ['']
    elif not emails_file:
        emails_file = ['']

    dist_email = __levenshtein__(str(emails_seed[0]), str(emails_file[0]))
    for email_s in emails_seed:
        for email_f in emails_file:
            dist_email = min(str(dist_email), str(__levenshtein__(str(email_s), str(email_f))))
    return float(dist_email)


# Method computing distance where name_servers are measured with "taking the minimun distance techniques "
def get_diff_name_servers_by_min_dist(name_servers_a=[], name_servers_b=[]):
    if name_servers_a is None:
        name_servers_a = []
    if name_servers_b is None:
        name_servers_b = []
    name_servers_seed = name_servers_a.split(',') if not isinstance(name_servers_a, list) else name_servers_a
    name_servers_file = name_servers_b.split(',') if not isinstance(name_servers_b, list) else name_servers_b
    if not name_servers_seed and not name_servers_file:
        return float(0)
    elif not name_servers_seed:
        name_servers_seed = ['']
    elif not name_servers_file:
        name_servers_file = ['']

    dist_name_server = __levenshtein__(str(name_servers_seed[0]), str(name_servers_file[0]))
    for name_server_s in name_servers_seed:
        for name_server_f in name_servers_file:
            dist_name_server = min(str(dist_name_server), str(__levenshtein__(str(name_server_s), str(name_server_f))))
    return float(dist_name_server)


def features_domains_attr(domain_name_a, registrar_a, name_a, orgs_a, zipcodes_a, creation_date_a,
                          expiration_date_a, emails_str_a, name_servers_str_a,
                          domain_name_b, registrar_b, name_b, orgs_b, zipcodes_b, creation_date_b,
                          expiration_date_b, emails_str_b, name_servers_str_b, ):
    dist_domain_name = __dist_domain__name__(domain_name_a, domain_name_b)
    dist_registrar = __dist_registrar__(registrar_a, registrar_b)
    dist_name = __dist_name__(name_a, name_b)
    dist_org = round(__dist_org_by_min_dist__(orgs_a, orgs_b),2)
    dist_zipcode = round(__dist_zipcode_by_min_dist__(zipcodes_a, zipcodes_b),2)
    diff_ttl = round(get_diff_ttl(creation_date_a, creation_date_b,expiration_date_a, expiration_date_b),2)
    diff_emails = round(get_diff_emails_by_min_dist(emails_str_a, emails_str_b),2)
    diff_name_servers = round(get_diff_name_servers_by_min_dist(name_servers_str_a,name_servers_str_b),2)
    dict_result = dict(dist_domain_name=dist_domain_name,
                  dist_registrar=dist_registrar,
                  dist_name=dist_name,
                  dist_org=dist_org,
                  dist_zipcode=dist_zipcode,
                  dist_duration= diff_ttl,
                  diff_emails=diff_emails,
                  diff_name_servers=diff_name_servers)
    return dict_result, [dist_domain_name, dist_registrar, dist_name, dist_org, dist_zipcode,
                         diff_ttl, diff_emails, diff_name_servers]


def features_domains(whois_info_a={}, whois_info_b={}):
    # reload(sys)
    # sys.setdefaultencoding("utf-8")
    domain_name_a = whois_info_a.get(KEY_DOMAIN_NAME,'')
    registrar_a = whois_info_a.get(KEY_REGISTRAR,'')
    name_a = whois_info_a.get(KEY_NAME,'')
    orgs_a = whois_info_a.get(KEY_ORG,[])   # []
    zipcode_a = whois_info_a.get(KEY_ZIPCODE,[])  # []
    creation_date_a = whois_info_a.get(KEY_CREATION_DATE,None)
    expiration_date_a = whois_info_a.get(KEY_EXPIRATION_DATE,None)
    emails_a = whois_info_a.get(KEY_EMAILS, [])  # []
    name_servers_a = whois_info_a.get(KEY_NAME_SERVERS, [])  # []

    domain_name_b = whois_info_b.get(KEY_DOMAIN_NAME, '')
    registrar_b = whois_info_b.get(KEY_REGISTRAR, '')
    name_b = whois_info_b.get(KEY_NAME, '')
    orgs_b = whois_info_b.get(KEY_ORG, [])  # []
    zipcode_b = whois_info_b.get(KEY_ZIPCODE, [])  # []
    creation_date_b = whois_info_b.get(KEY_CREATION_DATE, '')
    expiration_date_b = whois_info_b.get(KEY_EXPIRATION_DATE, '')
    emails_b = whois_info_b.get(KEY_EMAILS, [])  # []
    name_servers_b = whois_info_b.get(KEY_NAME_SERVERS, [])  # []

    return features_domains_attr(domain_name_a, registrar_a, name_a, orgs_a, zipcode_a, creation_date_a,
                         expiration_date_a, emails_a,name_servers_a,
                         domain_name_b, registrar_b, name_b, orgs_b, zipcode_b, creation_date_b,
                         expiration_date_b, emails_b, name_servers_b)


def distance_obj(whois_info_a, whois_info_b):
    feature_values = features_domains(whois_info_a, whois_info_b)
    # multiply = list(np.multiply(feature_values, weights))
    # sum_features = sum(multiply)
    sum_features = dot(feature_values,weights)
    return abs(sum_features)


def distance_domains(external_module,domain_a, domain_b):
    whois_info_a = WhoisConsult.get_features_info(external_module,domain_a)
    whois_info_b = WhoisConsult.get_features_info(external_module,domain_b)
    return distance_obj(whois_info_a, whois_info_b)

betaHat = np.array([[0.87492571], [-0.01038355], [0.0074585], [-0.03251031], [-0.01302924],
                    [-0.00868465],[-0.01016456],[0.01610108], [-0.01456118]])


# linear regression alg
def train_distance_weights(whois_objs, reg_factor=0.0001):
    inputs = []
    target = []
    for dmf in whois_objs:
        inputs.append([1] + dmf.get_features().values())
        target.append(dmf.related)

    number_features = len(whois_objs[0].get_features().keys()) + 1
    X = np.array(inputs)
    m = len(inputs)
    y = np.array(target).reshape(-1, 1)
    return train_distance_weights_arrays(X,y, reg_factor, number_features)

# linear regression alg
def train_distance_weights_arrays(X,y, reg_factor, nf=9):
    iden = np.identity(nf) * reg_factor
    dot = X.T.dot(X) + iden
    inv = np.linalg.inv(dot)
    betaHat = inv.dot(X.T).dot(y)
    return betaHat


def score_distance(X,y):
    return r2_score(y, predict_by_features(X),multioutput='variance_weighted')

# linear regression alg
def distance_related_decision_func(whois_info_a, whois_info_b,weigths):
    feature_values = np.append([1],features_domains(whois_info_a, whois_info_b)[1])
    return predict_by_features(feature_values,weigths)


# using linear regression alg
def predict_by_features(feature_values,weigths=betaHat):
    if not weigths:
        weigths = betaHat
    X = feature_values
    # print(feature_values)
    # N = len(feature_values)
    # X = np.c_[np.ones(N), feature_values]
    # input = np.array([1] + feature_values)
    # r = weigths.T.dot(input)
    r = safe_sparse_dot(X, weigths)
    return r


# linear regression alg
def distance_related(whois_info_a, whois_info_b,weigths=None):
    r = distance_related_decision_func(whois_info_a, whois_info_b,weigths)
    return True if r[0] > 0.5 else False


# linear regression alg
def distance_related_by_whois_obj(external_module,domain_a, domain_b,weigths=None):
    whois_info_a = WhoisConsult.get_features_info(external_module, domain_a)
    whois_info_b = WhoisConsult.get_features_info(external_module, domain_b)
    return distance_related(whois_info_a, whois_info_b,weigths)


def get_whois_information_features_of(external_module, domains):
    for domain in domains:
        WhoisConsult.get_features_info(external_module,domain)

