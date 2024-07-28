"""
This script runs first.

It will scroll through hacktivity until the appearance of URL of the first report in data.csv.
Then script searches for all new reports' URLs and add them to data.csv.

To use it without modifications you should put non-empty data.csv file
in the same directory with this script (current data.csv is good), because
scrolling through the whole hacktivity is almost impossible for now.
"""

import time
import csv
from datetime import datetime
from selenium.webdriver import Chrome, ChromeOptions
from selenium.webdriver.common.by import By

hacktivity_url = 'https://hackerone.com/hacktivity/overview'
page_loading_timeout = 10


def extract_reports(raw_reports):
    reports = []
    for raw_report in raw_reports:
        html = raw_report.get_attribute('href')
        try:
            index = html.index('/reports/')
        except ValueError:
            continue
        link = 'hackerone.com'
        for i in range(index, len(html)):
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
    options.binary_location = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    options.add_argument('no-sandbox')
    options.add_argument('headless')
    driver = Chrome(options=options)

    reports = []
    with open('data.csv', 'r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            reports.append(dict(row))
    first_report_link = reports[0]['link']


    try:
        driver.get(hacktivity_url)
        time.sleep(page_loading_timeout)

        page = 0
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        next_page_button = driver.find_element(By.CSS_SELECTOR, 'button[data-testid=\'hacktivity-next-button\']')
        new_reports = []
        while True:
            raw_reports = driver.find_elements(By.CLASS_NAME, 'routerlink')
            new_reports += extract_reports(raw_reports)
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
            driver.execute_script("arguments[0].click();", next_page_button)
            time.sleep(page_loading_timeout)
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
    except Exception as e:
        print(e)
        now = datetime.now().strftime('%Y-%m-%d')
        driver.get_screenshot_as_file('error-%s.png' % now)
    finally:
        driver.close()

    with open('data.csv', 'w', newline='', encoding='utf-8') as file:
        keys = reports[0].keys()
        writer = csv.DictWriter(file, fieldnames=keys)
        writer.writeheader()
        writer.writerows(reports)


if __name__ == '__main__':
    fetch()
