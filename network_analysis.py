import csv
import time
import os 
from datetime import datetime

class NetworkAnalyzer:
  def __init__(self, filename="network_stats.csv"): #placeholder file name
    self.filename = filename

    # Creates CSV file with headers if one isnt existing
    if not os.path.exists(self.filename):
      with open(self.filename, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Date", "Client", "Operation", "Filename", "File Size (MB)", "Transfer Time (Seconds)", "Transfer Rate (MB/s)", "Response Time (Seconds)"])
