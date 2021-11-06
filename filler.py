"""
This script runs third.

It will get every report in json and take necessary information.
It takes a lot of time to fetch because there are so much reports.

To use it without modifications you should put non-empty data.csv file
in the same directory with this script (current data.csv is good).
"""

import csv
import requests


def fill():
    reports = []
    with open('data.csv', 'r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            reports.append(dict(row))
    count_of_reports = len(reports)
    for i in range(count_of_reports):
        print('Fetching report ' + str(i + 1) + ' out of ' + str(count_of_reports))
        report_url = 'https://' + reports[i]['link'] + '.json'
        try:
            json_info = requests.get(report_url).json()
            reports[i]['title'] = json_info['title']
            reports[i]['program'] = json_info['team']['profile']['name']
            reports[i]['upvotes'] = int(json_info['vote_count'])
            reports[i]['bounty'] = float(json_info['bounty_amount']) if json_info['has_bounty?'] else 0.0
            reports[i]['vuln_type'] = json_info['weakness']['name'] if 'weakness' in json_info else ''
        except Exception:
            print('error at report ' + str(i + 1))
            continue

        print(reports[i])

    with open('data.csv', 'w', newline='', encoding='utf-8') as file:
        keys = reports[0].keys()
        writer = csv.DictWriter(file, fieldnames=keys)
        writer.writeheader()
        writer.writerows(reports)


if __name__ == '__main__':
    fill()
