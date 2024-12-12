"""
This script runs third.

It will get every report in json and take necessary information.
It takes a lot of time to fetch because there are so much reports.

To use it without modifications you should put non-empty data.csv file
in the same directory with this script (current data.csv is good).
"""

import csv
import requests
import time
import argparse

def create_argument_parser():
    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        '--update-all',
        action='store_true',
        help='Update all reports',
        default=False
    )
    argparser.add_argument(
        '--input-data-file',
        type=str,
        help='Path to input data file',
        default='data.csv'
    )
    argparser.add_argument(
        '--output-data-file',
        type=str,
        help='Path to output data file',
        default='data.csv'
    )
    return argparser

def fill(commandline_args):
    fetched_reports = []
    new_reports = []
    with open(commandline_args.input_data_file, 'r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row['title'] == '' or commandline_args.update_all:
                new_reports.append(dict(row))
            else:
                fetched_reports.append(dict(row))
    count_of_reports = len(new_reports)
    for i in range(count_of_reports):
        time.sleep(0.5)
        print('Fetching report ' + str(i + 1) + ' out of ' + str(count_of_reports))
        report_url = 'https://' + new_reports[i]['link'] + '.json'
        try:
            json_info = requests.get(report_url).json()
            new_reports[i]['title'] = json_info['title']
            new_reports[i]['program'] = json_info['team']['profile']['name']
            new_reports[i]['upvotes'] = int(json_info['vote_count'])
            new_reports[i]['bounty'] = float(json_info['bounty_amount'] if 'bounty_amount' in json_info else "0") if json_info['has_bounty?'] else 0.0
            new_reports[i]['vuln_type'] = json_info['weakness']['name'] if 'weakness' in json_info else ''
        except Exception as err:
            print('error at report ' + str(i + 1), err)
            continue

        print(new_reports[i])

    with open(commandline_args.output_data_file, 'w', newline='', encoding='utf-8') as file:
        reports = new_reports + fetched_reports
        keys = reports[0].keys()
        writer = csv.DictWriter(file, fieldnames=keys)
        writer.writeheader()
        writer.writerows(reports)


if __name__ == '__main__':
    parser = create_argument_parser()
    args = parser.parse_args()
    fill(args)
