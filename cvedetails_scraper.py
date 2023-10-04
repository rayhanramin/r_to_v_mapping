import requests
import csv
from bs4 import BeautifulSoup
from prettytable import PrettyTable

# Initialize a list to store IDs that encountered errors during processing
errored_ids = []

# Define user agent headers for web requests
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'DNT': '1',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1'
}


# Function to retrieve and process vulnerability IDs from a CSV file
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

        # Iterate through rows and extract the vuln_id column
        for row in csv_reader:
            if len(row) > 2:
                vuln_id = row[2]
                if vuln_id not in vuln_list:
                    vuln_list.append(vuln_id)
                    url = create_url(vuln_id)
                    scan_webpage(url, vuln_id)

    else:
        print(f"Failed to retrieve data. Status code: {response.status_code}")


# Function to create a URL for a vulnerability ID
def create_url(vuln_id):
    url = "https://www.cvedetails.com/cve/" + vuln_id + "/?q=" + vuln_id
    return url


# Function to extract summary text from a webpage
def grab_summary(soup, vuln_id):
    try:
        summary_text = soup.find(class_='ssc-paragraph cvedetailssummary-text text-dark pb-4 pt-2')
        summary_text = summary_text.get_text()
    except AttributeError:
        errored_ids.append(vuln_id)
        print(errored_ids)
        return
    return summary_text


# Function to extract the CWE ID from a webpage
def grab_cwe(soup, vuln_id):
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


# Function to extract Bugzilla links from a webpage
def grab_references(soup):
    links = [a_tag['href'] for a_tag in soup.select('li.list-group-item.list-group-item-action > a.ssc-ext-link') if a_tag.has_attr('href')]
    filtered_links = [link for link in links if "bugzilla" in link]
    filtered_links_string = '\n'.join(filtered_links)
    return filtered_links_string


# Function to scan and process a webpage
def scan_webpage(cve_details, vuln_id):
    response = requests.get(cve_details, headers=HEADERS)

    # Check if the request was successful
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')

        summary_text = grab_summary(soup, vuln_id)

        # Find the scores associated with the vuln_id
        scores = soup.find_all(class_='ps-2')
        try:
            base_score = scores[0].div.get_text()
            exploitability_score = scores[3].div.get_text()
            impact_score = scores[4].div.get_text()
        except IndexError:
            return
        # Use a try statement here to check if more than one set of scores exists
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

        # Find all headers containing the target text
        headers = soup.find_all(lambda tag: tag.name == 'h2' and target_header_text in tag.text)

        # Initialize lists to store data
        vendor_links = []
        product_links = []
        matching_versions_list = []
        vendor_names = []
        product_names = []

        # Iterate through the headers
        for header in headers:
            # Initialize empty lists to store links and titles for this section
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

            # Append data to respective lists
            vendor_links.extend(links[::3])
            product_links.extend(links[1::3])
            matching_versions_list.extend(links[2::3])
            vendor_names.extend(titles[::2])
            product_names.extend(titles[1::2])

        # Prepend "www.cvedetails.com" to each entry in the lists
        vendor_links_with_prefix = ["www.cvedetails.com" + link for link in vendor_links]
        product_links_with_prefix = ["www.cvedetails.com" + link for link in product_links]
        matching_versions_with_prefix = ["www.cvedetails.com" + link for link in matching_versions_list]

        # Convert the lists to strings with newlines
        vendor_links_str = "\n".join(vendor_links_with_prefix)
        product_links_str = "\n".join(product_links_with_prefix)
        matching_versions_str = "\n".join(matching_versions_with_prefix)
        vendor_names_str = "\n".join(vendor_names)
        product_names_str = "\n".join(product_names)

        # Add the data to the PrettyTable
        cve_details_table.add_row([vuln_id, summary_text, base_score, exploitability_score, impact_score, cwe_id,
                                   references_string, vendor_names_str, vendor_links_str, product_names_str,
                                   product_links_str, matching_versions_str])

    else:
        print(f"Failed to retrieve data from {cve_details}. Status code: {response.status_code}")

# Create a PrettyTable with headers
cve_details_table = PrettyTable(["Vulnerability ID", "Summary Text", "Base Score", "Exploitability Score",
                                     "Impact Score", "CWE ID", "Bugzilla Links", "Vendor Name", "Vendor Link",
                                     "Product Name", "Product Link", "Matching Versions"])

# Call the function to retrieve and process vulnerability IDs
grab_vuln_id()

# Write the data to a CSV file
with open("cve_details_table.csv", "w", newline='') as csvfile:
    csvfile.write(cve_details_table.get_csv_string())
