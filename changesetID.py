import requests
from bs4 import BeautifulSoup
import csv
from prettytable import PrettyTable

def gotomozilla(url):
    response = requests.get(url)
    html_code = response.content

    # Use BeautifulSoup to parse the HTML code
    soup = BeautifulSoup(html_code, 'html.parser')

    # Find the table
    table = soup.find('table')
    for i in range(1, 1240):
        rows = table.find_all('tr')
        current_row = rows[i]

        columns = current_row.find_all('td')
        second_column = columns[1]
        third_column = columns[2]
        fourth_column = columns[3]

        # Extract the text
        bugID  = second_column.get_text()
        bugURL = third_column.get_text()
        vulnID = fourth_column.get_text()
        changesetID = search_webpage_for_changesetID(bugURL)

        bug_vuln_changeset_table.add_row(([bugID, bugURL, vulnID, changesetID]))


def search_webpage_for_changesetID(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')

    # Shorten the URL to use when searching for the changesetID
    shortenedURl = str(url)[-33:]

    a_tags = soup.find_all('a', {'class': 'list'})
    for a_tag in a_tags:
        if shortenedURl in a_tag['href']:
            changesetID = a_tag.text
            return changesetID

bug_vuln_changeset_table = PrettyTable(["BugID", "Bug ID Link", "Vulnerability ID", "Changeset ID"])

url = 'https://github.com/rayhanramin/r_to_v_mapping/blob/main/Bug%20Vulnerability%20Table.csv'

gotomozilla(url)

with open("bug_vuln_changeset_table.csv", "w", newline='') as csvfile:
    csvfile.write(bug_vuln_changeset_table.get_csv_string())