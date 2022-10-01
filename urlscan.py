import requests
import json
import vt
import os
def urlscan(url):
    headers = {'API-Key':'4be401b4-9e6c-4886-bf2c-cf354c226823','Content-Type':'application/json'}
    data = {"url": url, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
    response_json = response.json()
    response_url = response_json['result']
    return response_url

##########################virustotal#################################################################################
def vts_url(url):
    client = vt.Client("df5258471dd63dcd21c6490a2b3e096578ec9ddc00c01e4dc354a49098a2e2d1")
    url_id = vt.url_id(url)

    urlr = client.get_object("/urls/{}", url_id)
    raw_result = urlr.last_analysis_stats
    malicious_url = str(raw_result['malicious'])
    harmless_url = str(raw_result['harmless'])
    # result = "Virustotal result is : " + malicious + " malicious " + harmless + ' harmless'
    return malicious_url, harmless_url

def res_url(url):
    response_url = urlscan(url)
    malicious_url, harmless_url = vts_url(url)
    raw_result_url = f'''
    Virustotal scan :
        harmless   =   {harmless_url}
        malicious  =   {malicious_url}
        '''
    result = ''

    if int(malicious_url) > 2 :
        result_url = "This url is malicious"
    else:
        result_url = "This  url isn't malicious"

    return result_url, raw_result_url, response_url
