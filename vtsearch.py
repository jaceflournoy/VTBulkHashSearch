import requests
import pprint as pp
from tqdm import tqdm

# Search term (hash), File Name, File Type, Response, Scan Date, Community Reputation, Detections, Total, Permalink

url = 'https://www.virustotal.com/vtapi/v2/file/report'
VT_API_KEY = '<VT_API_KEY>'

hashfile = open('hashes.txt', 'r')
vtresults = open('vtresults.txt','w+')
print("Searching VT for hashes...")
for hash in tqdm(hashfile, desc="Progress"):
    hash.split("\n")
    params = {'apikey': VT_API_KEY,
              'resource': hash,
              'allinfo': 'true'}
    response = requests.get(url, params=params)
    response = response.json()
    # pp.pprint(response)
    if response['response_code'] == 0:
        vtresults.write("---\nSearch Term: " + hash  + "\nSubmission Response: " + str(response['response_code']) +"\n" + "No Results Found, double check the hash" +"\n---\n\n")
    else:
        if len(response['submission_names'])<1:
            submissionName = "No File Name Found"
        else:
            submissionName = str(response['submission_names'][0])
        fileType = str(response['type'])
        scanDate = str(response['scan_date'])
        communityRep = str(response['community_reputation'])
        detections = str(response['positives'])
        totalResults = str(response['total'])
        permalink = str(response['permalink'])
        submissionResponse = str(response['response_code'])
        searchTerm = str(hash)
        vtresults.write("---\nSearch Term: " + searchTerm  + "\nSubmission Response: " + submissionResponse +"\n" + "File/Submission Name: " + submissionName + "\n" + "File Type: " + fileType + "\n" + "Scan Date: " + scanDate + "\n" + "Community Reputation: " + communityRep + "\n" + "Positive Detections: " + detections + "\n" + "Total Results: " + totalResults + "\n" + "Permalink: " + permalink + "\n" + "---\n\n")

hashfile.close()
vtresults.close()