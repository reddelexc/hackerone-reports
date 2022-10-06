"""
This script runs fourth (optional).

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
        file.write('Top 100 upvoted reports from HackerOne:\n\n')
        for i in range(0, 100):
            report = upvotes_sorted_reports[i]
            file.write(
                '{0}. [{1}](https://{2}) to {3} - {4} upvotes, ${5}\n'.format(i + 1, report['title'], report['link'],
                                                                              report['program'],
                                                                              report['upvotes'], int(report['bounty'])))


def top_100_paid(reports):
    bounty_sorted_reports = list(reversed(sorted(reports, key=lambda k: (k['bounty'], k['upvotes']))))
    with open('tops_100/TOP100PAID.md', 'w', encoding='utf-8') as file:
        file.write('Top 100 paid reports from HackerOne:\n\n')
        for i in range(0, 100):
            report = bounty_sorted_reports[i]
            file.write(
                '{0}. [{1}](https://{2}) to {3} - ${4}, {5} upvotes\n'.format(i + 1, report['title'], report['link'],
                                                                              report['program'],
                                                                              int(report['bounty']), report['upvotes']))


def top_by_bug_type(reports, bug_type, bug_name, keywords):
    filtered_reports = [report for report in reports if check_title(clean_title(report['title']), keywords)]
    for filtered_report in filtered_reports:
        index.append(filtered_report['link'])
    bug_sorted_reports = list(reversed(sorted(filtered_reports, key=lambda k: (k['upvotes'], k['bounty']))))
    with open('tops_by_bug_type/TOP{0}.md'.format(bug_type), 'w', encoding='utf-8') as file:
        file.write('Top {0} reports from HackerOne:\n\n'.format(bug_name))
        for i in range(0, len(bug_sorted_reports)):
            report = bug_sorted_reports[i]
            file.write('{0}. [{1}](https://{2}) to {3} - {4} upvotes, ${5}\n'
                       .format(i + 1, report['title'], report['link'], report['program'], report['upvotes'], int(report['bounty'])))


def top_by_program(reports, program):
    filtered_reports = [report for report in reports if report['program'] == program]
    bug_sorted_reports = list(reversed(sorted(filtered_reports, key=lambda k: (k['upvotes'], k['bounty']))))
    with open('tops_by_program/TOP{0}.md'.format(program.upper().replace('.', '').replace('-', '').replace(' ', '')),
              'w', encoding='utf-8') as file:
        file.write('Top reports from {0} program at HackerOne:\n\n'.format(program))
        for i in range(0, len(bug_sorted_reports)):
            report = bug_sorted_reports[i]
            file.write('{0}. [{1}](https://{2}) to {3} - {4} upvotes, ${5}\n'
                       .format(i + 1, report['title'], report['link'], report['program'], report['upvotes'], int(report['bounty'])))


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
    top_by_bug_type(reports, 'ACCOUNTTAKEOVER', 'Account Takeover', ['account takeover', 'ato'])
    top_by_bug_type(reports, 'BUSINESSLOGIC', 'Business Logic',
        ['functional', 'logic', 'function', 'functionality', 'manipulating response', 'response manipulation', 'manipulation'])
    top_by_bug_type(reports, 'API', 'REST API', ['api', 'rest api', 'restapi'])
    top_by_bug_type(reports, 'GRAPHQL', 'GraphQL', ['graphql', 'graphql api', 'api graphql'])
    top_by_bug_type(reports, 'INFODISCLOSURE', 'Information Disclosure',
        ['information disclosure', 'infos disclosure', 'user information', 'pii'])
    top_by_bug_type(reports, 'WEBCACHE', 'Web Cache', ['web cache poisoning', 'web cache', 'web cache deception'])
    top_by_bug_type(reports, 'SSTI', 'SSTI', ['ssti', 'server side template injection'])
    top_by_bug_type(reports, 'UPLOAD', 'Upload', ['upload', 'unrestricted file upload', 'file upload'])
    top_by_bug_type(reports, 'REQUESTSMUGGLING', 'Request Smuggling', ['request smuggling', 'http request smuggling'])
    top_by_bug_type(reports, 'OPENID', 'OpenID', ['openid', 'saml', 'sso'])
    top_by_bug_type(reports, 'MOBILE', 'Mobile', ['mobile', 'android', 'ios', 'apk'])
    top_by_bug_type(reports, 'FILEREADING', 'File Reading',
        ['lfi', 'rfi', 'file reading', 'path', 'traversal', 'file inclusion'])
    top_by_bug_type(reports, 'AUTHORIZATION', 'Authorization Bypass',
        ['authorization bypass', 'authorization', 'able to access', 'access control', 'ability',
        'privilege', 'escalation', 'admin', 'unauthorized', 'permission'])
    top_by_bug_type(reports, 'AUTH', 'Authentication', ['authentication bypass', 'authentication', 'auth'])
    top_by_bug_type(reports, 'MFA', 'MFA', ['mfa', '2fa', 'two factor', 'two_factor', 'multi factor', 'multi_factor'])

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
