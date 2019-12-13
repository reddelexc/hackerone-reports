"""
This script runs second.
Works via headless Chrome, so you should add path of chromedriver executable to the PATH.

It will open every report page and scrap necessary information.
It takes several hours to complete as there are almost 7000 reports already.
Works via splitting page text by regexp and then accessing tokens by indexes in array, so it's pretty unstable.

To use it without modifications you should put non-empty data.csv file
in the same directory with this script (current data.csv is good).
"""

import csv
import re
from selenium.webdriver import Chrome, ChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

page_loading_timeout = 10
regex = re.compile('<.*?>')
split_regex = re.compile(r'\s{2,}')


def fill():
    reports = []
    with open('data.csv', 'r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            reports.append(dict(row))
    options = ChromeOptions()
    options.add_argument('headless')
    driver = Chrome(options=options)
    count_of_reports = len(reports)
    for i in range(count_of_reports):
        print('Fetching report ' + str(i + 1) + ' out of ' + str(count_of_reports))
        report_url = 'https://' + reports[i]['link']
        driver.get(report_url)
        try:
            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, 'routerlink')))
        except Exception:
            print('error at report ' + str(i + 1))
            continue
        raw_info = driver.find_elements_by_class_name('report-heading')[0]
        html = raw_info.get_attribute('innerHTML')
        text = re.sub(regex, ' ', html)
        tokens = re.split(split_regex, text)
        print(tokens)
        try:
            reported_to_index = tokens.index('Reported To')
            reports[i]['program'] = tokens[reported_to_index + 1]
        except Exception:
            pass
        reports[i]['title'] = tokens[5].replace('<', '\<').replace('>', '\>')
        reports[i]['upvotes'] = int(tokens[3])
        try:
            bounty_index = tokens.index('Bounty')
            reports[i]['bounty'] = float(tokens[bounty_index + 1][1:].replace(',', ''))
        except Exception:
            pass
        print(reports[i])

    with open('data.csv', 'w', newline='', encoding='utf-8') as file:
        keys = reports[0].keys()
        writer = csv.DictWriter(file, fieldnames=keys)
        writer.writeheader()
        writer.writerows(reports)


if __name__ == '__main__':
    fill()
