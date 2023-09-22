import requests
import csv
from bs4 import BeautifulSoup
from prettytable import PrettyTable

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'DNT': '1',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1'
}


def grab_vuln_id():
    # Use the raw version of the CSV file
    response = requests.get("https://raw.githubusercontent.com/rayhanramin/r_to_v_mapping/main/bug_vuln_changeset_table.csv")

    vuln_list = []
    # Check if the request was successful
    if response.status_code == 200:
        content = response.content.decode('utf-8')
        csv_reader = csv.reader(content.splitlines(), delimiter=',')

        # Skip the header row
        next(csv_reader)

        # Iterate through rows and extract the fourth column
        for row in csv_reader:
            if len(row) > 2:
                vuln_id = row[2]
                if vuln_id != "XBL-scopes":
                    if vuln_id not in vuln_list:
                        vuln_list.append(vuln_id)
                        url = create_url(vuln_id)
                        scan_webpage(url, vuln_id)

    else:
        print(f"Failed to retrieve data. Status code: {response.status_code}")


def create_url(vuln_id):
    url = "https://www.cvedetails.com/cve/" + vuln_id + "/?q=" + vuln_id
    return url


def scan_webpage(cve_details, vuln_id):
    response = requests.get(cve_details, headers=HEADERS)

    # Check if the request was successful
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find content by class name
        summary_text = soup.find(class_='ssc-paragraph cvedetailssummary-text text-dark pb-4 pt-2')
        scores = soup.find_all(class_='ps-2')
        base_score = scores[0].div.get_text()
        exploitability_score = scores[3].div.get_text()
        impact_score = scores[4].div.get_text()

        #links = soup.find(class_='whatever the links are')
        #for link in links:
            #if link includes 'mozilla'
                #add link to table
            #else
                #add N/A to table



        cve_details_table.add_row(([vuln_id, ]))


        if summary_text:
            print(summary_text.get_text())
        else:
            print(f"No summary text found for {cve_details}")
    else:
        print(f"Failed to retrieve data from {cve_details}. Status code: {response.status_code}")

cve_details_table = PrettyTable([vuln_id, ])

grab_vuln_id()
