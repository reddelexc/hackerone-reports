"""
This script runs second.

It will remove duplicate report entries.
"""

import csv

uniques = set()
result = []
fieldnames = []

with open('data.csv', 'r', newline='') as file:
	reader = csv.DictReader(file)
	fieldnames = reader.fieldnames
	for row in reader:
		if row['link'] not in uniques:
			uniques.add(row['link'])
			result.append(row)
	
with open('data.csv', 'w', newline='') as file:
	writer = csv.DictWriter(file, fieldnames=fieldnames)
	writer.writeheader()
	writer.writerows(result)
