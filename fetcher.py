"""
This script runs first.
Works via headless Chrome, so you should add path of chromedriver executable to the PATH.

It will scroll through hacktivity until the appearance of URL of the first report in data.csv.
Then script searches for all new reports' URLs and add them to data.csv.

To use it without modifications you should put non-empty data.csv file
in the same directory with this script (current data.csv is good), because
scrolling through the whole hacktivity is almost impossible for now.
"""

import time
import csv
from selenium.webdriver import Chrome, ChromeOptions

hacktivity_url = 'https://hackerone.com/hacktivity?order_field=latest_disclosable_activity_at&filter=type%3Apublic'
page_loading_timeout = 10


def extract_reports(raw_reports):
    reports = []
    for raw_report in raw_reports:
        html = raw_report.get_attribute('innerHTML')
        try:
            index = html.index('hackerone.com/reports/')
        except ValueError:
            continue
        link = ''
        for i in range(index, index + 50):
            if html[i] == '"':
                break
            else:
                link += html[i]
        report = {
            'program': '',
            'title': '',
            'link': link,
            'upvotes': 0,
            'bounty': 0.,
            'vuln_type': ''
        }
        reports.append(report)

    return reports


def fetch():
    options = ChromeOptions()
    options.add_argument('no-sandbox')
    options.add_argument('headless')
    driver = Chrome(options=options)

    reports = []
    with open('data.csv', 'r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            reports.append(dict(row))
    first_report_link = reports[0]['link']

    driver.get(hacktivity_url)
    driver.implicitly_wait(page_loading_timeout)

    counter = 0
    page = 0
    last_height = driver.execute_script("return document.body.scrollHeight")
    while True:
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(page_loading_timeout)
        new_height = driver.execute_script("return document.body.scrollHeight")
        if new_height == last_height:
            counter += 1
            if counter > 1:
                break
        else:
            counter = 0
        last_height = new_height

        raw_reports = driver.find_elements_by_class_name('fade')
        new_reports = extract_reports(raw_reports)
        found = False
        for i in range(len(new_reports)):
            if new_reports[i]['link'] == first_report_link:
                reports = new_reports[:i] + reports
                found = True
                break
        if found:
            break

        page += 1
        print('Page:', page)

    driver.close()

    with open('data.csv', 'w', newline='', encoding='utf-8') as file:
        keys = reports[0].keys()
        writer = csv.DictWriter(file, fieldnames=keys)
        writer.writeheader()
        writer.writerows(reports)


if __name__ == '__main__':
    fetch()
