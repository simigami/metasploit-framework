import csv
import pandas as pd

data = pd.read_csv("./report.csv")

data = data.drop(['Hostname', 'Solution Type','Other References', 'NVT OID', 'Task Name',
 'Timestamp','Result ID', 'Impact', 'Solution', 'Affected Software/OS', 'Vulnerability Detection Method', 
 'Product Detection Result', 'BIDs', 'CERTs', 'Task ID', 'Severity'], axis = 1)

data.dropna(inplace=True)

data.to_csv("./report.csv", index = False)

print(data.columns)