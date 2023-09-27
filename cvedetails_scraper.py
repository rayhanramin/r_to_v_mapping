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

        print(vuln_id)

        # Find content by class name
        try:
            summary_text = soup.find(class_='ssc-paragraph cvedetailssummary-text text-dark pb-4 pt-2')
            summary_text = summary_text.get_text()
        except AttributeError:
            return

        scores = soup.find_all(class_='ps-2')
        try:
            base_score = scores[0].div.get_text()
            exploitability_score = scores[3].div.get_text()
            impact_score = scores[4].div.get_text()
        except IndexError:
            return

        try:
            if scores[5]:
                base_score = base_score + "\n" + scores[5].div.get_text()
                exploitability_score = exploitability_score + "\n" + scores[8].div.get_text()
                impact_score = impact_score + "\n" + scores[9].div.get_text()
        except IndexError:
            pass

        # Check to see if there is a CWE id associated with the vuln_id
        h2_tag = soup.find('h2', string="CWE ids for " + vuln_id)
        if h2_tag:
            cwe = soup.find(class_='list-group-item list-group-item-action')
            if cwe:
                cwe_id = cwe.a.get_text()
            else:
                cwe_id = "N/A"
        else:
            cwe_id = "N/A"

        # Find all the references for the vuln_id and shorten it to just bugzilla links
        links = [a_tag['href'] for a_tag in soup.select('li.list-group-item.list-group-item-action > a.ssc-ext-link') if
                 a_tag.has_attr('href')]

        filtered_links = [link for link in links if "bugzilla" in link]
        filtered_links_string = '\n'.join(filtered_links)



        cve_details_table.add_row(([vuln_id, summary_text, base_score, exploitability_score, impact_score, cwe_id,
                                    filtered_links_string]))
                                    #vendor_name, vendor_link, product_name, product_link, matching_versions]))

    else:
        print(f"Failed to retrieve data from {cve_details}. Status code: {response.status_code}")

cve_details_table = PrettyTable(["Vulnerability ID", "Summary Text", "Base Score", "Exploitability Score", "Impact Score", "CWE ID",
                                 "Bugzilla Links"])
                                 #"Vendor Name", "Vendor Link", "Product Name", "Product Link",
                                 #"Matching Versions"])

grab_vuln_id()

with open("cve_details_table.csv", "w", newline='') as csvfile:
    csvfile.write(cve_details_table.get_csv_string())
