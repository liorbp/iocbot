__author__ = 'beepi'

from queryable import *

import requests
import time
from datetime import datetime
from math import ceil
from Queue import Queue, Empty
from threading import Thread

class PrivateVTQueryable(Queryable):
    _alias = "vtpriv"
    _name = 'VirusTotal - Private API'

    def get_hash_info(self, q, results_list):
        '''
        Gets each and every hash information from VT's API

        :return: List
        '''
        hashes_list = []
        # My preferred AV's priority
        engines_list = ['Microsoft', 'TrendMicro', 'Symantec', 'ESET-NOD32', 'McAfee']

        while q.qsize() > 0:
            for i in range(25):
                try:
                    hashes_list.append(q.get_nowait())
                except Empty:
                    break

            params = {'apikey': self.settings['api_key'], 'resource': ','.join(hashes_list)}
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
            json_response = response.json()

            # If one result returned - put it in a list
            if isinstance(json_response, dict):
                # When searching for hash only, verify it exists first
                if response_json['response_code'] <= 0 :
                    return None
                json_response = [json_response,]

            for item in json_response:
                hash_id = item['scan_id']
                hash_scan_date = item['scan_date']
                hash_permalink = item['permalink']
                hash_positives = item['positives']
                hash_total = item['total']
                formatted_scan_date = datetime.strptime(hash_scan_date, '%Y-%m-%d %H:%M:%S')
                hash_result = None

                # Looking for the most suitable AV generic signature of the hash
                for engine in engines_list:
                    try:
                        if item['scans'][engine]['result']:
                            hash_result = [engine, item['scans'][engine]['result']]
                            break
                    # Catch KeyError in case engine doesn't exists
                    except KeyError:
                        continue

                r = Record()
                r.id = hash_id
                r.datetime = time.mktime(formatted_scan_date.timetuple())
                r.description = 'Unknown'
                r.data = 'Detection Ratio: {}/{}\n' \
                         'Permalink: {}'.format(hash_positives, hash_total, hash_permalink),

                # Add description if hash was detected by one of the major AVs
                if hash_result:
                    r.description = '{} detected it as {}'.format(hash_result[0], hash_result[1])

                results_list.append(r)


    def _query(self, phrase):
        '''
        Implement the way we search through VT's Private API

        :return: List
        '''

        q = Queue()
        workers_list = []
        results_list = []

        if phrase.type == QueryPhrase.TYPE_HASH:
            q.put(phrase.data)
        # Using VT's search API for anything that isn't of type hash
        else:
            params = {'apikey': self.settings['api_key'], 'query': phrase.data}
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/search', params=params)
            response_json = response.json()
            if response_json['response_code'] <= 0 :
                return None

            for hash in response_json['hashes'][:self.settings['max_results']]:
                q.put(hash)

        # Calculates number of threads needed (1 thread for each 25 hashes)
        num_threads = int(ceil(float(q.qsize())/25))

        for i in range(num_threads):
            worker = Thread(target=self.get_hash_info, args=(q, results_list))
            workers_list.append(worker)
            worker.start()

        for w in workers_list:
            w.join()

        return results_list


import requests
import time
from datetime import datetime

class PublicVTQueryable(Queryable):
    _alias = "vtpub"
    _name = 'VirusTotal - Public API'

    def parse_field(self, items, description, phrase_data):
        '''
        Parses all lines of one VT field and builds one record object out of it

        :return: Queryable record object
        '''
        data = []

        for item in items[:self.settings['max_results']]:
            positives = item['positives']
            total = item['total']

            if 'scan_date' in item:
                date = item['scan_date']
            elif 'date' in item:
                date = item['date']
            else:
                date = None

            if 'url' in item:
                resource = item['url'].replace('http://','hXXp://')
            elif 'sha256' in item:
                resource = item['sha256']
            else:
                resource = None

            line = 'Detection: {}/{} | {date}Resource: {}'.format(positives, total, resource, date='{} | '.format(date) if date else '')
            data.append(line)

        data = '\n'.join(data)

        r = Record()
        r.description = description
        r.data = data

        r.id = ' - https://www.virustotal.com/en/search?query={}'.format(phrase_data)
        r.datetime = 1

        return r


    def _query(self, phrase):
        '''
        Implement the way we search through VT's Public API

        :return: List
        '''

        params = {'apikey': self.settings['api_key']}

        if phrase.type == QueryPhrase.TYPE_IP:
            params['ip'] = phrase.data
            url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

        elif phrase.type == QueryPhrase.TYPE_DOMAIN:
            params['domain'] = phrase.data
            url = 'https://www.virustotal.com/vtapi/v2/domain/report'

        elif phrase.type == QueryPhrase.TYPE_URL:
            params['resource'] = phrase.data
            url = 'https://www.virustotal.com/vtapi/v2/url/report'

        elif phrase.type == QueryPhrase.TYPE_HASH:
            #raise ValueError("Please use VT Private API for hash lookup")
            return None
        elif phrase.type == QueryPhrase.TYPE_MAIL:
            #raise ValueError("VT Public API doesn't support email format")
            return None
        else:
            return None

        response = requests.get(url, params=params)
        response_json = response.json()
        if response_json['response_code'] <= 0 :
            return None

        results_list = []
        fields = {
            'detected_urls': 'Latest URLs hosted in this IP address',
            'detected_communicating_samples': 'Latest detected files that communicate with this IP address',
            'detected_downloaded_samples': 'Latest detected files that were downloaded from this IP address',
            'detected_referrer_samples': 'Latest detected files that embed this IP address in their strings',
            'undetected_communicating_samples': 'Latest undetected files that communicate with this IP address',
            'undetected_downloaded_samples': 'Latest undetected files that were downloaded from this IP address',
            'undetected_referrer_samples': 'Latest undetected files that embed this IP address in their strings',
        }

        for field, desc in fields.iteritems():
            try:
                field = response_json[field]
                r = self.parse_field(field, desc, phrase.data)
                results_list.append(r)
            except KeyError:
                continue

        # If no significant information found in VT, returns resource's detection ratio
        if not results_list:
            try:
                resource_id = response_json['scan_id']
                resource_scan_date = response_json['scan_date']
                hash_permalink = response_json['permalink']
                resource_positives = response_json['positives']
                resource_total = response_json['total']
                formatted_scan_date = datetime.strptime(resource_scan_date, '%Y-%m-%d %H:%M:%S')

                r = Record()
                r.id = resource_id
                r.datetime = time.mktime(formatted_scan_date.timetuple())
                r.description = 'Detection Ratio:   {} / {}'.format(resource_positives, resource_total)
                #r.data = 'Permalink: https://www.virustotal.com/en/search?query={}'.format(phrase.data)
                r.data = 'Permalink: {}'.format(hash_permalink)

                results_list.append(r)
            except ValueError:
                return None

        return results_list


import requests
import time
from datetime import datetime

class FWatchPortalQueryable(Queryable):
    _alias = "portal"
    _name = 'FirstWatch Threat Portal'

    def _query(self, phrase):
        '''
        Implement the way we search through FirstWatch Threat Portal

        :return: List
        '''

        portal_api = 'http://{}:{}/api/record/get'.format(self.settings['host_ip'], self.settings['host_port'])
        params = {'token': self.settings['token'], 'resource': phrase.data}
        response = requests.get(portal_api, params=params)
        if response.text == 'found 0 matching records':
            return None

        response_json = response.json()
        results_list = []

        for collection in response_json[:self.settings['max_results']]:
            collection_name = collection['collection']

            for record in collection['data']:
                threat_id = record['_id']['$oid']
                threat_date_added = (record['date_added']['$date'] / 1000)
                formatted_date_added = datetime.fromtimestamp(threat_date_added)
                threat_description = record['threat_description']
                threat_category = record['threat_category']
                threat_source = record['threat_source']

                comments = ''
                for comment in record['comments']:
                    comments += '\n"{}" commented by {}'.format(comment['text'], comment['author'])

                r = Record()
                r.id = threat_id
                r.datetime = time.mktime(formatted_date_added.timetuple())
                r.description = 'Found in collection: {}'.format(collection_name)

                r.data = 'Threat Description: {}\nThreat Category: {}\nThreat Source: {}\n{}'.format(threat_description, threat_category, threat_source, comments)

                results_list.append(r)

        return results_list


import MySQLdb
import MySQLdb.cursors

class ATSIncQueryable(Queryable):
    _alias = "atsinc"
    _name = 'ATSInc'

    def build_select(self, data):
        '''
        Building the select query for MYSQL database

        :return:
            SQL query as Format String
            SELECT fields in a Tuple
        '''

        select_tuple = ()
        columns = ['host_drop', 'host_ip', 'drop_url', 'infection_url', 'config_url', 'md5', 'analysis', 'comments']
        query = 'SELECT {0}.id, {0}.create_date, {0}.drop_url, trojan_family.family_name ' \
                'FROM {1}.{0} ' \
                'LEFT JOIN {1}.trojan_family ' \
                'ON {0}.trojan_family_id =  trojan_family.id ' \
                'WHERE '.format(self.settings['table'], self.settings['db'])

        for field in columns:
            select_tuple += ('%{}%'.format(data),)
            query += '({} LIKE %s)'.format(field)
            if field != columns[-1]:
                query += ' OR '

        query += 'LIMIT {}'.format(self.settings['max_results'])

        return query, select_tuple


    def _query(self, phrase):
        '''
        Implement the way we search through ATSInc

        :return: List
        '''

        # Avoid searching for phrase less than 4 chars
        if len(phrase.data) < 4:
            #raise ValueError('Phrase must be at least 4 characters long')
            return None

        db = MySQLdb.connect(self.settings['host'], self.settings['user'], self.settings['pass'], self.settings['db'],
                             cursorclass=MySQLdb.cursors.DictCursor)
        cur = db.cursor()

        query, select_tuple = self.build_select(phrase.data)

        cur.execute(query, select_tuple)
        rows = cur.fetchall()

        results_list = []

        for row in rows:
            row_id = int(row['id'])
            row_creation_date = row['create_date']
            row_trojan_family = row['family_name']
            row_drop_url = row['drop_url'].replace('http://','hXXp://')

            r = Record()
            r.id = row_id
            r.datetime = time.mktime(row_creation_date.timetuple())
            r.description = 'Resource related to {} Trojan'.format(row_trojan_family)
            r.data = 'Drop-Point URL: {}'.format(row_drop_url)

            results_list.append(r)

        return results_list


import ast
import re
import urllib2
from urllib import urlencode

class SpartaQueryable(Queryable):
    _alias = "sparta"
    _name = 'Sparta'

    def basic_auth_connect(self, url, username, password):
        '''
        Implement an HTTP basic auth connection for req_solr

        :return: urllib2 response object
        '''

        password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
        password_mgr.add_password(None, url, username, password)
        auth_handler = urllib2.HTTPBasicAuthHandler(password_mgr)
        opener = urllib2.build_opener(auth_handler)
        urllib2.install_opener(opener)
        conn = urllib2.urlopen(url)

        return conn


    def add_get_params(self, select, fields="*", resp_format="python"):
        get_params = {'qt': 'dist',
                     'q': select,
                     'fl': fields,
                     'rows': self.settings['max_results'],
                     'wt': resp_format,
                     'omitHeader': 'true'
                     }
        get_params = urlencode(get_params)

        return get_params


    def req_solr(self, get_params):
        '''
        Implement the way we query Apache Solr

        :return: database response as Dict
        '''

        url = self.settings['url'] + "/select?" + get_params

        conn = self.basic_auth_connect(url,self.settings['user'],self.settings['pass'])
        response = ast.literal_eval(conn.read())
        if response['response']['numFound']:
            return response


    def _query(self, phrase):
        '''
        Implement the way we search through Sparta

        :return: List
        '''

        query = "domain:{0} OR host:{0} OR ip:{0} OR url:{0} OR dropPointUrl:{0} OR emails:{0}".format(re.escape(phrase.data))
        get_params = self.add_get_params(query, "id, creationDate, trojanFamilyName, dropPointUrl, stolenDate")

        sparta_result = self.req_solr(get_params)

        if sparta_result:
            results_list = []

            for document in sparta_result['response']['docs']:
                doc_id = document['id']
                doc_creation_date = document['creationDate']
                doc_trojan_type = document['trojanFamilyName']
                doc_drop_url = document['dropPointUrl'].replace('http://','hXXp://')
                doc_stolen_date = document['stolenDate']

                formatted_stolen_date = datetime.strptime(doc_stolen_date, '%Y-%m-%dT%H:%M:%SZ')
                try:
                    formatted_creation_date = datetime.strptime(doc_creation_date, '%Y-%m-%dT%H:%M:%S.%fZ')
                except ValueError:
                    formatted_creation_date = datetime.strptime(doc_creation_date, '%Y-%m-%dT%H:%M:%SZ')

                r = Record()
                r.id = doc_id
                r.datetime = time.mktime(formatted_creation_date.timetuple())
                r.description = 'Resource related to {} Trojan'.format(doc_trojan_type)
                r.data = 'Exfiltrated data sent to URL: {} @ {}'.format(doc_drop_url, formatted_stolen_date)

                results_list.append(r)

            return results_list


'''
class ExampleFeedQueryable(Queryable):
    _alias = "example"
    _name = 'Example Feed'

    def _query(self, data):

    	Your logic goes here...

        for item in list:
	        r = Record()
	        r.id = 1234
	        r.datetime = '1234567890'
	        r.description = 'Found indication evilness all over'
	        r.data ='Evil data is evil'
	        results_list.append(r)
        
        return results_list
'''
