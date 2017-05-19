#!/usr/bin/python

import csv
import sys
import MySQLdb as my
from datetime import * 


#  findremediated.py is a a Nessus Scanner tool to identify changes from scan to scan if a vulnerability is no longer seen 
#  against a known IP address that was in fact scanned, then it will be assumed remediated, updated, and exported to report.

 
db = my.connect(host="127.0.0.1",      # Open connection to scan database
user="scanner",
passwd="Scanner01!!",
db="scanner"
)
 
cursor = db.cursor()
 
csv_escape_table = {                   # Function to escape characters from the CSV to import into MySQL
    '"': "\'\'\'",
    "'": "\"",
    }

def csv_escape(text):
    """Produce entities within text."""
    return "".join(csv_escape_table.get(c,c) for c in text)

####################################  Magic Starts Here #######################################################


# execute SQL query using execute() method.
cursor.execute("select * from scans WHERE Mitigated_On = '' ")
 
# Fetch a single row using fetchone() method.
data = cursor.fetchall()
for i in range(2):            #temporary, only grab a few rows to test
    print(i)
    for row in data:
       scankey = row[0]
       plugin = row[2]
       ipaddress = row[3]
       port = row[4]
       protocol = row[5]
       scandate = row[9]
       mitigated = row[11]
       print "ScanKey: ", scankey
       print "Source Plugin: ", plugin , "IP Address: ", ipaddress, "ScanDate: ", scandate
 
  
      # Find the last date this vulnerability was seen on this IP address.    
       sqlmax = "SELECT MAX(Scan_Date) FROM scans scans WHERE \
         Plugin = '%s' AND IP_Address = '%s' AND Port = '%s' AND Protocol = '%s'" % (plugin,ipaddress,port,protocol)
       cursor.execute(sqlmax)
       row = cursor.fetchone()
       lastdate=row[0]
       print "Last Date: ", lastdate

       cutoff = date.today()-timedelta(days=60)       # pick a suitable timeframe for this.. ie 45 days
       print "Cutoff: ", str(cutoff),  "last date: ", lastdate
 
       if str(cutoff) > lastdate:                   # If the last date seen is older than cutoff, update the Mitigated_On field
          # print cutoff

           print "Cutoff: ", cutoff,  "last date: ", lastdate
           sql2 = "UPDATE scans SET Mitigated_On = '%s' WHERE \
            Plugin = '%s' AND IP_Address = '%s' AND Port = '%s' AND Protocol = '%s' AND Mitigated_On = ''" % (lastdate, plugin,ipaddress,port,protocol)
           number_of_rows = cursor.execute(sql2)

           db.commit()

db.close()



