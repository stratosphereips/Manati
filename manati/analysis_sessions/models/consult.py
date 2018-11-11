# Copyright (C) 2016-2018 Stratosphere Lab
# This file is part of ManaTI Project - https://stratosphereips.org
# See the file 'docs/LICENSE' for copying permission.
# Created by Raul B. Netto <raulbeni@gmail.com> on 8/25/18.
from django.db import models
from .base import TimeStampedModel
from .app_parameter import AppParameter
from django.db import transaction
import json
import datetime
from django.core import management
from jsonfield import JSONField
from django.contrib.auth.models import User
from django.utils import timezone
from model_utils import Choices
import pythonwhois
import dateutil
from pythonwhois.shared import WhoisException
from manati.share_modules.util import get_domain_by_obj, get_data_from_url
from manati.share_modules.virustotal import vt
from ipwhois import IPWhois
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
import re
vt = vt()


class VTConsultManager(models.Manager):

    @transaction.atomic
    def create_one_consult(self, query_node, user, line_report):
        with transaction.atomic():
            info = line_report.split(";")
            index = 0
            info_report_obj = {}
            for elem in info:
                info_report_obj[VTConsult.KEYS_INFO[index]] = elem
                index += 1
            VTConsult.objects.create(query_node=query_node, user=user, info_report=json.dumps(info_report_obj))


class VTConsult(TimeStampedModel):
    KEYS_INFO = ["IP", "Rating", "Owner", "Country Code", "Log Line No", "Positives", "Total", "Malicious Samples",
                 "Hosts"]
    query_node = models.CharField(max_length=100, null=False)
    info_report = JSONField(default=json.dumps({}), null=False)
    user = models.ForeignKey(User)

    objects = VTConsultManager()

    @staticmethod
    def get_query_info(query_node, user, query_type):
        vt_consul = VTConsult.objects.filter(query_node=query_node,
                                             created_at__gt=timezone.now() - timezone.timedelta(days=15)).first()
        if vt_consul is None:
            if query_type == 'ip':
                management.call_command('virustotal_checker', "--nocsv", "--nocache", ff=query_node, user=user)
                vt_consul = VTConsult.objects.filter(query_node=query_node,
                                                     created_at__gt=timezone.now() - timezone.timedelta(
                                                         days=15)).first()
            elif query_type == 'domain':
                api_key = user.profile.virustotal_key_api
                if not api_key:
                    api_key = AppParameter.objects.get(key=AppParameter.KEY_OPTIONS.virus_total_key_api).value
                vt.setkey(api_key)
                result = vt.getdomain(query_node)
                vt.setkey(None)
                vt_consul = VTConsult.objects.create(query_node=query_node, user=user, info_report=json.dumps(result))
            else:
                raise ValueError("query_type invalid")
        return vt_consul

    class Meta:
        db_table = 'manati_virustotal_consults'

    def __unicode__(self):
        return unicode(self.info_report) or u''


class WhoisConsult(TimeStampedModel):
    QUERY_TYPES = Choices(('ip', 'IP'), ('domain', 'Domain'), )
    query_node = models.CharField(max_length=100, null=False)
    query_type = models.CharField(max_length=20, null=False, choices=QUERY_TYPES)
    info_report = JSONField(null=True)
    features_info = JSONField(null=True)  # pythonwhois
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)  # User or ExternalModule
    object_id = models.IntegerField()
    content_object = GenericForeignKey('content_type', 'object_id')

    def __process_result_by_domain__(self, domain, save=True):  # python whois lib
        d = domain
        try:
            if not self.info_report and d:
                r = pythonwhois.get_whois(d)
                self.info_report = r
            elif not d:
                print("PW, domain null " + str(d) + " " + str(self.id))
                self.info_report = {}
        except WhoisException as e:
            print("PW rejects " + str(d) + " " + str(self.id) + ", ERROR TRACE " + e.message)
            self.info_report = {}
        except:
            self.info_report = {}
            print("PW rejects " + str(d) + " " + str(self.id))

        if save:
            self.save()

    def check_info_report(self, domain, save=True):
        if not self.info_report:
            self.__process_result_by_domain__(domain, save=save)
        return self.info_report

    # python whois
    def process_features_by_domain(self, domain, save=True):
        result = self.check_info_report(domain, save=save)
        raw = result.get('raw', None)
        raw = raw[0].split('\n') if not raw is None else []
        try:
            raw = ','.join(raw).encode('utf-8').strip().split(',')
        except UnicodeDecodeError as e:
            print(raw)
            raw = ','.join(raw).encode('ascii', 'ignore').decode('ascii').strip().split(',')

        # self.features_info_pw

        def get_dict(dict_obj, key, default):
            value = dict_obj.get(key, type(default))
            if not isinstance(value, type(default)) and not type(default) == None:
                return default
            else:
                return value

        def get_emails():
            emails = result.get('emails', [])
            emails = [] if emails is None else emails
            emails = emails.split(',') if not isinstance(emails, list) else emails
            return emails

        def get_domain_name():
            pattern = r'^.*Domain Name:.*$'
            indices = [i for i, x in enumerate(raw) if re.search(pattern, x)]
            fields = str(raw[indices[0]]).split(':') if len(indices) > 0 else []
            domain_name = fields[1].strip() if len(fields) > 0 else ''
            if not domain_name or domain_name == '':
                _, domain_name = get_data_from_url(self.query_node)
                domain_name = domain_name if domain_name else ''
            return domain_name

        def get_name_servers():
            ns = result.get('nameservers', [])
            ns = ns.split(',') if isinstance(ns, basestring) else ns
            return ns

        def get_registrar():
            registrar = result.get('registrar', '')
            if not registrar or registrar == '':
                pattern = r'^.*Registrar:.*$'
                indices = [i for i, x in enumerate(raw) if re.search(pattern, x)]
                fields = str(raw[indices[0]]).split(':') if len(indices) > 0 else []
                registrar = fields[1].strip() if len(fields) > 0 else ''
            return registrar[0] if isinstance(registrar, list) else registrar

        def get_name():
            contacts = get_dict(result, 'contacts', {})
            name_admin = get_dict(contacts, 'admin', {}).get('name', '')
            name_tech = get_dict(contacts, 'tech', {}).get('name', '')
            name_registrant = get_dict(contacts, 'registrant', {}).get('name', '')
            names = list(set([name_admin, name_tech, name_registrant]))
            names = [n for n in names if n or not n == '']
            name = names[0] if len(names) > 0 else ''
            if not name or name == '':
                pattern = r'^.*name:.*$'
                indices = [i for i, x in enumerate(raw) if re.search(pattern, x)]
                names = []
                for indice in indices:
                    fields = str(raw[indice]).split(':') if len(indices) > 0 else []
                    names.append(fields[1].strip() if len(fields) > 0 else '')
                return names[0] if len(names) > 0 else ''
            else:
                return name

        def get_creation_date():
            cd_str = result.get('creation_date', [])
            if cd_str and len(cd_str) > 0:
                if isinstance(cd_str[0], basestring):
                    try:
                        return dateutil.parser.parse(cd_str[0])
                    except:
                        print("Date Invalid ", self.id, cd_str[0])
                        return None
                elif isinstance(cd_str[0], datetime.datetime):
                    return cd_str[0]
            else:
                return None

        def get_expiration_date():
            ed_str = result.get('expiration_date', [])
            if ed_str and len(ed_str) > 0:
                if isinstance(ed_str[0], basestring):
                    try:
                        return dateutil.parser.parse(ed_str[0])
                    except:
                        print("Date Invalid ", self.id, ed_str[0])
                        return None
                elif isinstance(ed_str[0], datetime.datetime):
                    return ed_str[0]
            else:
                return None

        def get_zipcodes():
            contacts = get_dict(result, 'contacts', {})
            postalcode_admin = get_dict(contacts, 'admin', {}).get('postalcode', '')
            postalcode_tech = get_dict(contacts, 'tech', {}).get('postalcode', '')
            postalcode_registrant = get_dict(contacts, 'registrant', {}).get('postalcode', '')
            return list(set([postalcode_admin, postalcode_tech, postalcode_registrant]))

        def get_orgs():
            contacts = get_dict(result, 'contacts', {})
            org_admin = get_dict(contacts, 'admin', {}).get('organization', '')
            org_tech = get_dict(contacts, 'tech', {}).get('organization', '')
            org_registrant = get_dict(contacts, 'registrant', {}).get('organization', '')
            return list(set([org_admin, org_tech, org_registrant]))

        if not self.features_info:
            features = dict(
                emails=get_emails(),
                domain_name=get_domain_name(),
                name_servers=get_name_servers(),
                registrar=get_registrar(),
                name=get_name(),
                creation_date=get_creation_date(),
                expiration_date=get_expiration_date(),
                zipcode=get_zipcodes(),
                org=get_orgs()
            )
            self.features_info = features
            if save:
                self.save()

    @staticmethod
    def get_whois_distance_features_by_domain(content_object, domain_name):
        query_type = 'domain'
        whois_objs = WhoisConsult.objects.filter(query_node=domain_name, query_type=query_type)
        if whois_objs.exists():
            whois = whois_objs.first()
        else:
            whois = WhoisConsult.objects.create(query_node=domain_name, query_type=query_type,
                                                content_object=content_object)
        return whois.whois_distance_features()

    def whois_distance_features(self):
        features = self.check_features_info().copy()
        del features['creation_date']
        del features['expiration_date']
        features['duration'] = self.domain_duration()
        return features

    def domain_duration(self):
        if self.features_info:
            creation_date_a = self.features_info['creation_date']
            expiration_date_a = self.features_info['expiration_date']
            if not creation_date_a or not expiration_date_a:
                return None
            cd_a = dateutil.parser.parse(creation_date_a) if not isinstance(creation_date_a,
                                                                            datetime.datetime) else creation_date_a
            ed_a = dateutil.parser.parse(expiration_date_a) if not isinstance(expiration_date_a,
                                                                              datetime.datetime) else expiration_date_a
            if cd_a and ed_a:
                return float(abs(cd_a - ed_a).days)
            else:
                return None

    def process_features_by_ip(self, ip):
        pass

    def check_features_info(self, save=True):
        if not self.features_info:
            self.process_features_by_domain(self.query_node, save=save)
        return self.features_info

    @staticmethod
    def get_features_info_by_set_url(content_object, urls_or_ips):
        query_ips = []
        query_domains = []
        result = {}
        for url_or_ip in urls_or_ips:
            query_type, query_node = get_data_from_url(url_or_ip)
            if query_type == 'ip':
                query_ips.append(query_node)
            elif query_type == 'domain':
                query_domains.append(query_node)
            result[query_node] = {}

        with transaction.atomic():
            # domain
            whois_objs = WhoisConsult.objects.filter(query_node__in=query_domains, query_type='domain')
            query_node_created = []
            for whois_obj in whois_objs:
                result[whois_obj.query_node] = whois_obj.check_features_info()
                query_node_created.append(whois_obj.query_node)

            whois_objs = []
            for query_node in query_domains:
                if not query_node in query_node_created:
                    whois_objs.append(WhoisConsult(query_node=query_node,
                                                   query_type='domain',
                                                   content_object=content_object))
            WhoisConsult.objects.bulk_create(whois_objs)
            for whois_obj in whois_objs:
                result[whois_obj.query_node] = whois_obj.check_features_info()

            # bulk_update(whois_objs)

            # ip TO-DO by IP
            # whois_objs_ip = WhoisConsult.objects.filter(query_node__in=query_domains, query_type='ip')
            for query_node in query_ips:
                result[query_node] = {}

        return result

    @staticmethod
    def get_features_info(content_object, url_or_ip):
        query_type, query_node = get_data_from_url(url_or_ip)
        if not query_node:
            return {}
        elif query_type == 'domain':
            return WhoisConsult.get_features_info_by_domain(content_object, query_node)
        elif query_type == 'ip':
            # TO-DO IP version
            return {}
        else:
            pass

    @staticmethod
    def get_features_info_by_domain(content_object, domain_name):
        query_type = 'domain'
        whois_objs = WhoisConsult.objects.filter(query_node=domain_name, query_type=query_type)
        if whois_objs.exists():
            whois = whois_objs.first()
        else:
            whois = WhoisConsult.objects.create(query_node=domain_name, query_type=query_type,
                                                content_object=content_object)

        if not whois.features_info:
            whois.process_features_by_domain(domain_name)
        features = whois.features_info
        return features

    @staticmethod
    def __get_query_info__(query_node, user, **kwargs):

        class ComplexEncoder(json.JSONEncoder):
            def default(self, obj):
                if hasattr(obj, 'reprJSON'):
                    return obj.reprJSON()
                if hasattr(obj, 'isoformat'):
                    return obj.isoformat()
                else:
                    return json.JSONEncoder.default(self, obj)

        whois_consult = WhoisConsult.objects.filter(query_node=query_node,
                                                    created_at__gt=timezone.now() - timezone.timedelta(
                                                        days=365)).first()
        if whois_consult is None:
            if 'ip' in kwargs:
                obj = IPWhois(query_node)
                results = obj.lookup()
                whois_consult = WhoisConsult.objects.create(query_node=query_node,
                                                            info_report=results,
                                                            content_object=user)
            elif 'domain' in kwargs:
                w = pythonwhois.get_whois(query_node)
                whois_consult = WhoisConsult.objects.create(query_node=query_node,
                                                            info_report=w,
                                                            content_object=user)
            else:
                raise ValueError(
                    "you must determine is you want to do a domain or ip consultation by __get_query_info" +
                    "__('query', SomeUser, domain=True or ip=True")
        whois_consult.check_info_report(query_node, save=True)

        return whois_consult

    @staticmethod
    def get_query_info_by_ip(query_node, user):
        return WhoisConsult.__get_query_info__(query_node, user, ip=True)

    @staticmethod
    def get_query_info_by_domain(query_node, user):
        return WhoisConsult.__get_query_info__(query_node, user, domain=True)

    @staticmethod
    def get_query_by_domain(query_node):
        user = User.objects.get(username='anonymous_user_for_metrics')
        return WhoisConsult.get_query_info_by_domain(query_node, user).info_report

    class Meta:
        db_table = 'manati_whois_consults'

    def __unicode__(self):
        return unicode(self.info_report) or u''
