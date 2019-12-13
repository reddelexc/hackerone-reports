"""
This script runs third (optional).

It simply takes info from data.csv and aggregate it.
You can use this script as an example to create your custom lists of reports.

To use it without modifications you should put non-empty data.csv file
in the same directory with this script (current data.csv is good).
"""

import csv

index = []


def clean_title(title):
    return ' '.join(title.split()).lower().replace('-', ' ').replace('—', ' ').replace(',', '').replace('.', '') \
        .replace(':', '').replace(';', '')


def check_title(title, keywords):
    for keyword in keywords:
        if len(keyword.split()) == 1:
            for word in title.split():
                if word == keyword:
                    return True
        else:
            if keyword in title:
                return True
    return False


def top_100_upvoted(reports):
    upvotes_sorted_reports = list(reversed(sorted(reports, key=lambda k: k['upvotes'])))
    with open('tops_100/TOP100UPVOTED.md', 'w', encoding='utf-8') as file:
        file.write('[Back](../README.md)\n\n')
        file.write('Top 100 upvoted reports from HackerOne:\n\n')
        for i in range(0, 100):
            report = upvotes_sorted_reports[i]
            file.write(
                '{0}. [{1}](https://{2}) to {3} - {4} upvotes, ${5}\n'.format(i + 1, report['title'], report['link'],
                                                                              report['program'],
                                                                              report['upvotes'], int(report['bounty'])))
        file.write('\n\n[Back](../README.md)')


def top_100_paid(reports):
    bounty_sorted_reports = list(reversed(sorted(reports, key=lambda k: (k['bounty'], k['upvotes']))))
    with open('tops_100/TOP100PAID.md', 'w', encoding='utf-8') as file:
        file.write('[Back](../README.md)\n\n')
        file.write('Top 100 paid reports from HackerOne:\n\n')
        for i in range(0, 100):
            report = bounty_sorted_reports[i]
            file.write(
                '{0}. [{1}](https://{2}) to {3} - ${4}, {5} upvotes\n'.format(i + 1, report['title'], report['link'],
                                                                              report['program'],
                                                                              int(report['bounty']), report['upvotes']))
        file.write('\n\n[Back](../README.md)')


def top_by_bug_type(reports, bug_type, bug_name, keywords):
    filtered_reports = [report for report in reports if check_title(clean_title(report['title']), keywords)]
    for filtered_report in filtered_reports:
        index.append(filtered_report['link'])
    bug_sorted_reports = list(reversed(sorted(filtered_reports, key=lambda k: (k['upvotes'], k['bounty']))))
    with open('tops_by_bug_type/TOP{0}.md'.format(bug_type), 'w', encoding='utf-8') as file:
        file.write('[Back](../README.md)\n\n')
        file.write('Top {0} reports from HackerOne:\n\n'.format(bug_name))
        for i in range(0, len(bug_sorted_reports)):
            report = bug_sorted_reports[i]
            file.write('{0}. [{1}](https://{2}) to {3} - {4} upvotes, ${5}\n'
                       .format(i + 1, report['title'], report['link'], report['program'], report['upvotes'], int(report['bounty'])))
        file.write('\n\n[Back](../README.md)')


def top_by_program(reports, program):
    filtered_reports = [report for report in reports if report['program'] == program]
    bug_sorted_reports = list(reversed(sorted(filtered_reports, key=lambda k: (k['upvotes'], k['bounty']))))
    with open('tops_by_program/TOP{0}.md'.format(program.upper().replace('.', '').replace('-', '').replace(' ', '')),
              'w', encoding='utf-8') as file:
        file.write('[Back](../README.md)\n\n')
        file.write('Top reports from {0} program at HackerOne:\n\n'.format(program))
        for i in range(0, len(bug_sorted_reports)):
            report = bug_sorted_reports[i]
            file.write('{0}. [{1}](https://{2}) to {3} - {4} upvotes, ${5}\n'
                       .format(i + 1, report['title'], report['link'], report['program'], report['upvotes'], int(report['bounty'])))
        file.write('\n\n[Back](../README.md)')


def main():
    reports = []
    max_title_length = 0
    with open('data.csv', 'r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            row_dict = dict(row)
            row_dict['bounty'] = float(row_dict['bounty'].replace('"', '').replace('$', '').replace(',', ''))
            row_dict['upvotes'] = int(row_dict['upvotes'])
            row_dict['title'] = row_dict['title'].replace('<', '\<').replace('>', '\>')
            if len(row_dict['title']) > max_title_length:
                max_title_length = len(row_dict['title'])
            reports.append(row_dict)
    print('Max title length:', max_title_length)

    top_100_upvoted(reports)
    top_100_paid(reports)

    top_by_bug_type(reports, 'XSS', 'XSS', ['css', 'xss', 'domxss', 'cross site scripting', ])
    top_by_bug_type(reports, 'XXE', 'XXE', ['xxe', 'xml external entity', 'xml entity'])
    top_by_bug_type(reports, 'CSRF', 'CSRF', ['csrf', 'xsrf', 'cross site request forgery'])
    top_by_bug_type(reports, 'IDOR', 'IDOR', ['idor', 'insecure direct object reference'])
    top_by_bug_type(reports, 'RCE', 'RCE', ['rce', 'remote code execution'])
    top_by_bug_type(reports, 'SQLI', 'SQLI', ['sqli', 'sql inj', 'sql command injection'])
    top_by_bug_type(reports, 'SSRF', 'SSRF', ['ssrf', 'server side request forgery'])
    top_by_bug_type(reports, 'RACECONDITION', 'Race Condition', ['race condition'])
    top_by_bug_type(reports, 'SUBDOMAINTAKEOVER', 'Subdomain Takeover',
                    ['domain takeover', 'domain takeover', 'domain take over'])
    top_by_bug_type(reports, 'OPENREDIRECT', 'Open Redirect', ['open redirect'])
    top_by_bug_type(reports, 'CLICKJACKING', 'Clickjacking', ['clickjacking', 'click jacking', 'clicjacking'])
    top_by_bug_type(reports, 'DOS', 'DoS', ['dos', 'denial of service', 'service denial'])
    top_by_bug_type(reports, 'OAUTH', 'OAuth', ['oauth'])

    programs = {}
    for report in reports:
        if report['program'] not in programs:
            programs[report['program']] = [report]
        else:
            programs[report['program']].append(report)
    top_programs = sorted(programs, key=lambda k: len(programs[k]), reverse=True)
    for program in top_programs[:35]:
        print(program)
        top_by_program(reports, program)

    count_of_not_indexed = 0
    for report in reports:
        if report['link'] not in index:
            count_of_not_indexed += 1
            print(report['title'])
    print('Count of all reports:', len(reports))
    print('Count of not indexed reports:', count_of_not_indexed)


if __name__ == '__main__':
    main()
