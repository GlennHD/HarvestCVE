import requests
import json
import pandas as pd


cve_list_input = ['CVE-2021-26855', 'CVE-2021-27078']
cve_data_output = 'output.json'

def get_CVEs_by_ID(cve_list_input):
  cve_list = []
  cve_url = 'https://services.nvd.nist.gov/rest/json/cve/1.0/'
  for cve in cve_list_input:
    url = cve_url + cve
    print("Searching for " + cve)
    response = (requests.get(url)).json()
    cve_list.append(response)
  return cve_list


def parse_cve_data(list_of_details):
  dict = {}
  for record in list_of_details:
    record_dict = {}
    if 'ID' in record['result']['CVE_Items'][0]['cve']['CVE_data_meta']:
      cveid = record['result']['CVE_Items'][0]['cve']['CVE_data_meta']['ID']
    if 'ASSIGNER' in record['result']['CVE_Items'][0]['cve']['CVE_data_meta']:
      record_dict.update({ "CVE_assigner": record['result']['CVE_Items'][0]['cve']['CVE_data_meta']['ASSIGNER'] })
    if 'CVE_data_timestamp' in record['result']:
      record_dict.update({ "CVE_date": record['result']['CVE_data_timestamp'] })
    if 'publishedDate' in record['result']['CVE_Items'][0]:
      record_dict.update({ "publishedDate": record['result']['CVE_Items'][0]['publishedDate'] })
    if 'lastModifiedDate' in record['result']['CVE_Items'][0]:
      record_dict.update({ "lastModifiedDate": record['result']['CVE_Items'][0]['lastModifiedDate'] })
    if 'description' in record['result']['CVE_Items'][0]['cve']:
      description = [ x for x in record['result']['CVE_Items'][0]['cve']['description']['description_data'] ]
      for desc in record['result']['CVE_Items'][0]['cve']['description']['description_data']:
        if desc['lang'] == 'en':
          record_dict.update({ 'description': desc['value'] })
      #record_dict.update({ 'description': [ x for x in record['result']['CVE_Items'][0]['cve']['description']['description_data'] ] })
    impact = { key:value for key,value in record['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3'].items() }
    cpes = [ x for x in record['result']['CVE_Items'][0]['configurations']['nodes'][0]['cpe_match'] ]
    refs = [ x for x in record['result']['CVE_Items'][0]['cve']['references']['reference_data'] ]
    record_dict.update({ 'impact': impact })
    record_dict.update({ 'cpes': cpes })
    record_dict.update({ 'references': refs })
    dict[cveid] = record_dict
  return dict


CVE_data = get_CVEs_by_ID(cve_list_input)
parsed = parse_cve_data(CVE_data)


with open(cve_data_output, 'w') as f:
  json.dump(parsed, f)