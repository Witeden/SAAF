import csv
import copy
from analyse_malware import getPatterns

CSV_FIELD_NAME = "name"
CSV_FIELD_IS_MALWARE = "isMalware"
CSV_FIELD_STATUS = "status"
CSV_FIELD_DATE = "date"

TAG_HEURISTIC_PATTERN = "heuristic-pattern"
TAG_BACKTRACK_PATTERN = "backtracking-pattern"

CONFIG_FILE_BACKTRACK_PATTERNS = "./conf/backtracking-patterns.xml"
CONFIG_FILE_HEURISTIC_PATTERNS = "./conf/heuristic-patterns.xml"

CSV_FIELDS = [CSV_FIELD_NAME, CSV_FIELD_IS_MALWARE, CSV_FIELD_STATUS, CSV_FIELD_DATE]

STAT_FILE_PATH = "./stat_file.csv"

def createStatFile():
    with open(STAT_FILE_PATH, "w") as file:
        writer = csv.DictWriter(file, fieldnames = getAllcsvFIELDS(), delimiter =',')
        writer.writeheader()

def getAllcsvFIELDS():
    cvs_fields = copy.deepcopy(CSV_FIELDS)
    with open (CONFIG_FILE_HEURISTIC_PATTERNS, 'r') as f:
        data = f.read()
        cvs_fields += getPatterns(data, TAG_HEURISTIC_PATTERN)
    with open (CONFIG_FILE_BACKTRACK_PATTERNS, 'r') as f:
        data = f.read()
        cvs_fields += getPatterns(data, TAG_BACKTRACK_PATTERN)
    return cvs_fields

def addRow(name, isMalware, status, date, patterns):
    with open(STAT_FILE_PATH, "a") as file:
        writer = csv.DictWriter(file, fieldnames = getAllcsvFIELDS(), delimiter = ',')
        newRow = {
            CSV_FIELD_NAME: name, 
            CSV_FIELD_IS_MALWARE: isMalware, 
            CSV_FIELD_STATUS: status,
            CSV_FIELD_DATE: date
        }
        newRow.update(patterns)
        writer.writerow(newRow)