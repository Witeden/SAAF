import csv

CSV_FIELD_NAME = "name"
CSV_FIELD_IS_MALWARE = "isMalware"
CSV_FIELD_STATUS = "status"
CSV_FIELD_DATE = "date"

CSV_FIELDS = [CSV_FIELD_NAME, CSV_FIELD_IS_MALWARE, CSV_FIELD_STATUS, CSV_FIELD_DATE]

STAT_FILE_PATH = "./stat_file.csv"

def createStatFile():
    with open(STAT_FILE_PATH, "w") as file:
        writer = csv.DictWriter(file, fieldnames = CSV_FIELDS)
        writer.writeheader()

def addRow(name, isMalware, status, date):
    with open(STAT_FILE_PATH, "a") as file:
        writer = csv.DictWriter(file, fieldnames = CSV_FIELDS)
        writer.writerow({
            CSV_FIELD_NAME: name, 
            CSV_FIELD_IS_MALWARE: isMalware, 
            CSV_FIELD_STATUS: status,
            CSV_FIELD_DATE: date
        })