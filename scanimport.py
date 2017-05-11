import csv
import sys
import MySQLdb as my
import json

#  csvreader.py is a a Nessus Scanner import tool to identify changes from scan to scan 
#  it expects the scan arguments to be in the following order
#  [0]Plugin,[1]Plugin [1]Name,[2]Family,[3]Severity,[4]IP Address,[5]Protocol,[6]Port,[7]Exploit,[8]'Repository', 
#  [9]'MAC Address', [10]'DNS Name', [11]'NetBIOS Name', [12]'Plugin Text', [13]'Synopsis', [14]'Description', 
#  [15]'Solution', [16]'See Also', [17]'Risk Factor', [18]'STIG Severity', [19]'CVSS Base Score', [20]'CVSS Temporal Score', 
#  [21]'CVSS Vector', [22]'CPE', [23]'CVE', [24]'BID', [25]'Cross References', [26]'First Discovered', [27]'Mitigated On', 
#  [28]'Vuln Publication Date', [29]'Patch Publication Date', [30]'Plugin Publication Date', [31]'Plugin Modification Date', 
#  [32]'Exploit Ease', [33]'Exploit Frameworks', [34]'Check Type', [35]'Version'


f = open(sys.argv[1], 'rt')            # Get Nessus CSV scan file from commandline

 
db = my.connect(host="127.0.0.1",      # Open connection to scan database
user="scanner",
passwd="Scanner",
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

try:
  reader = csv.reader(f)
  headerfields = next(reader)        # Get names of columns into 'headerfields[]'
  print headerfields                 # this is temporary, for debug, not a function of the actual app.
  for i in range(500000):
    row = next(reader)
    try:
      float(row[0])               # Valid rows start with a numeric column - value between 10000 and 100000 
    except ValueError:
      print("Not a valid row!")
      pass
    else:
      try:
        value = long(row[0])
      except ValueError:
        print("Value out of range!")
        pass
      else:
###############  Populate "plugins" table with newly seen plugin definitions ##################################
         if 10000 <= value <= 3000000:              # Valid range for Nessus Plugin values

           sql1 = "SELECT 'Plugin' FROM plugins WHERE Plugin = '%s'" % value
           if cursor.execute(sql1):                # Check to see if plugin already exists in database.
               print ("skipping plugin, already in DB\r")
           else: 
               jsonPlugin_Name = csv_escape(row[1])
               jsonSynopsis = csv_escape(row[13])     # Escape quotes in long strings for storage
               jsonDescription = csv_escape(row[14])
               jsonSolution = csv_escape(row[15])
              
#  [16]'See Also', [17]'Risk Factor', [18]'STIG Severity', [19]'CVSS Base Score', [20]'CVSS Temporal Score', 
#  [21]'CVSS Vector', [22]'CPE', [23]'CVE', [24]'BID', [25]'Cross References', [26]'First Discovered', [27]'Mitigated On', 
#  [28]'Vuln Publication Date', [29]'Patch Publication Date', [30]'Plugin Publication Date', [31]'Plugin Modification Date', 
#  [32]'Exploit Ease', [33]'Exploit Frameworks', [34]'Check Type', [35]'Version'




               plugin_sql = "insert into plugins (Plugin, Plugin_Name, Family, Severity, Protocol, Port, \
                              Exploit, Plugin_Text, Synopsis, Description, Solution, See_Also, Risk_Factor, CVE) \
               VALUES('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % \
               (value, csv_escape(row[1]), row[2],row[3],row[5],row[6],row[7], csv_escape(row[12]), \
               csv_escape(row[13]), csv_escape(row[14]),csv_escape(row[15]),csv_escape(row[16]), row[17], row[23])
               # print row                          # Debug
               try:               
                 number_of_rows = cursor.execute(plugin_sql)
               except ValueError:
                  print("SQL Error")
                  pass
               else:
                  db.commit()             # Insert new plugin into plugins table

###############  Populate "hosts" table with newly seen IP Addresses ###########################################
           sql2 = "SELECT 'IP_Address' FROM hosts WHERE inet_aton(IP_Address) = inet_aton('%s')" % row[4]
           if cursor.execute(sql2):                # Check to see if IP_Address already exists in database.
                                                   # ***** Future state: also needs to validate host/IP match !!!
               number_of_rows = cursor.execute(sql2)
               print (sql2)
               print (number_of_rows)
               print ("skipping IP Address, already stored \r")
           else: 

               host_sql = "insert into hosts (Hostname, IP_Address, MAC_Address, DNS_Name, NETBIOS_Name, \
                First_Discovered) VALUES('%s', '%s', '%s', '%s', '%s', '%s')" % \
               (row[10], row[4], row[9],row[10],row[11],row[26])
             #  print row
               try:               
                 number_of_rows = cursor.execute(host_sql)
               except ValueError:
                  print("SQL Error")
                  pass
               else:
                  db.commit()             # Insert new IP Address into hosts table



###############  Populate "scans" table with newly seen Nessus Scans ###########################################

           scan_sql = "insert into scans (Plugin, IP_Address, MAC_Address, DNS_Name, NETBIOS_Name, First_Discovered, Mitigated_On) VALUES('%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (value, row[4], row[9],row[10],row[11], row[26], row[27])
             #  print row
           try:               
             number_of_rows = cursor.execute(scan_sql)
           except ValueError:
              print("SQL Error")
              pass
           else:
              db.commit()             # Insert new IP Address into hosts table

             #  continue
         else:
            print ("Value out of range!")





finally:
    f.close()
    db.close()


