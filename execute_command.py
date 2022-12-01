from os import listdir
from os.path import isfile, join,abspath
import subprocess

from analyse_malware import getZipDate,getAnalysis
from handle_csv import addRow,createStatFile

def execute_command(command,malware_directory,report_directory,start=0,end=10,isMalware = False):
    createStatFile()
    file_directories = [f for f in listdir(malware_directory)[start:end] if isfile(join(abspath(malware_directory),f))]
    
    for file in file_directories:

        subprocess.run([command,"-hl",join(abspath(malware_directory),file)])

        
        if listdir(report_directory)!=[]:
            file_report = [r for r in listdir(report_directory)][0]
            status, patterns = getAnalysis(join(abspath(report_directory),file_report))
            date = getZipDate(join(abspath(malware_directory),file))

            subprocess.run(["rm",join(abspath(report_directory),file_report)])
            addRow(file.replace(".apk",""),isMalware,status,date, patterns)
        else:
            addRow(file.replace(".apk",""),isMalware,"EXECUTION_FAILED",date, patterns)

print(execute_command("./SAAF/scripts/run_saaf.sh","/media/jeremy/MalwareViolet/20kmalgood/mal","./SAAF/reports",start=0,end=100,isMalware=True))
