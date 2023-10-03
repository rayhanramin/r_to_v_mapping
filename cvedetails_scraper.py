import requests
import csv
from bs4 import BeautifulSoup
from prettytable import PrettyTable

errored_ids = []

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


def grab_summary(soup, vuln_id):
    # Find content by class name
    try:
        summary_text = soup.find(class_='ssc-paragraph cvedetailssummary-text text-dark pb-4 pt-2')
        summary_text = summary_text.get_text()
    except AttributeError:
        errored_ids.append(vuln_id)
        print(errored_ids)
        return
    return summary_text


def grab_cwe(soup, vuln_id):
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

    return cwe_id


def grab_references(soup):
    # Find all the references for the vuln_id and shorten it to just bugzilla links
    links = [a_tag['href'] for a_tag in soup.select('li.list-group-item.list-group-item-action > a.ssc-ext-link') if
             a_tag.has_attr('href')]

    filtered_links = [link for link in links if "bugzilla" in link]
    filtered_links_string = '\n'.join(filtered_links)
    return filtered_links_string


def scan_webpage(cve_details, vuln_id):
    response = requests.get(cve_details, headers=HEADERS)


    # Check if the request was successful
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')

        summary_text = grab_summary(soup, vuln_id)

        scores = soup.find_all(class_='ps-2')
        try:
            base_score = scores[0].div.get_text()
            exploitability_score = scores[3].div.get_text()
            impact_score = scores[4].div.get_text()
        except IndexError:
            return

        try:
            if scores[5]:
                base_score += "\n" + scores[5].div.get_text()
                exploitability_score += "\n" + scores[8].div.get_text()
                impact_score += "\n" + scores[9].div.get_text()
        except IndexError:
            pass

        cwe_id = grab_cwe(soup, vuln_id)

        references_string = grab_references(soup)

        # Define the header text you want to search for
        target_header_text = "Products affected by"

        # Find the first header containing the target text
        header = soup.find(lambda tag: tag.name == 'h2' and target_header_text in tag.text)

        # Iterate through the headers
        while header:
            # Initialize an empty list to store links
            links = []
            titles = []
            # Traverse the tree to find links within the specific section
            section = header.find_next('li', class_='list-group-item list-group-item-action')

            # Iterate through all 'li' elements in the section
            while section:
                link_elements = section.find_all('a', href=True)
                title_elements = section.find_all('a', title=True)

                for link_element in link_elements:
                    links.append(link_element['href'])

                for title_element in title_elements:
                    if title_element.get_text() != "Matching versions":
                        titles.append(title_element.get_text())

                # Find the next 'li' element (if any) in the same section
                section = section.find_next('li', class_='list-group-item list-group-item-action')

            for i, link in enumerate(links):
                if i == 0:
                    vendor_link = link
                elif i == 1:
                    product_link = link
                elif i == 2:
                    matching_versions = link
                elif i % 3 == 2:
                    matching_versions += "\n" + link
                elif i % 2 == 0:
                    vendor_link += "\n" + link
                elif i % 2 == 1:
                    product_link += "\n" + link

            for i, title in enumerate(titles):
                if i == 0:
                    vendor_name = title
                elif i == 1:
                    product_name = title
                elif i % 2 == 0:
                    vendor_name += "\n" + title
                elif i % 2 == 1:
                    product_name += "\n" + title


            # Find the next header (if any)
            header = header.find_next(lambda tag: tag.name == 'h2' and target_header_text in tag.text)


        cve_details_table.add_row(([vuln_id, summary_text, base_score, exploitability_score, impact_score, cwe_id,
                                    references_string, vendor_name, vendor_link, product_name, product_link,
                                    matching_versions]))

    else:
        print(f"Failed to retrieve data from {cve_details}. Status code: {response.status_code}")

cve_details_table = PrettyTable(["Vulnerability ID", "Summary Text", "Base Score", "Exploitability Score",
                                 "Impact Score", "CWE ID", "Bugzilla Links", "Vendor Name", "Vendor Link",
                                 "Product Name", "Product Link", "Matching Versions"])

grab_vuln_id()


with open("cve_details_table.csv", "w", newline='') as csvfile:
    csvfile.write(cve_details_table.get_csv_string())
