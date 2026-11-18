
import csv
import time
import os
import threading
from datetime import datetime


class NetworkAnalyzer:

    def __init__(self, filename="network_stats.csv"):
        self.filename = filename
        self.lock = threading.Lock()

        # Create CSV file with headers if it doesn't exist
        with self.lock:
            if not os.path.exists(self.filename):
                with open(self.filename, "w", newline="") as file:
                    writer = csv.writer(file)
                    writer.writerow([
                        "Date", "Client", "Operation", "Filename", "File Size (MB)", "Transfer Time (Seconds)", "Transfer Rate (MB/s)", "Response Time (Seconds)" ])

    def record_transfer(self, client, operation, filename,
                        file_size, transfer_time, response_time):

        # File size is supplied in MB
        if transfer_time > 0:
            transfer_rate = file_size / transfer_time
        else:
            transfer_rate = 0

        # Store statistics safely when multiple clients are connected
        with self.lock:
            with open(self.filename, "a", newline="") as file:
                writer = csv.writer(file)

                writer.writerow([
                    datetime.now(),
                    client,
                    operation,
                    filename,
                    round(file_size, 2),
                    round(transfer_time, 4),
                    round(transfer_rate, 2),
                    round(response_time, 4)
                ])

        print("\nNetwork Statistics Recorded")
        print("Operation:", operation)
        print("File:", filename)
        print("File Size:", file_size, "MB")
        print("Transfer Time:", transfer_time, "seconds")
        print("Transfer Rate:", round(transfer_rate, 2), "MB/s")
        print("Response Time:", response_time, "seconds")


# Example usage for testing the module separately
if __name__ == "__main__":

    analyzer = NetworkAnalyzer()

    start = time.perf_counter()
    time.sleep(2)
    transfer_time = time.perf_counter() - start

    analyzer.record_transfer(
        client="Client1",
        operation="Upload",
        filename="sample.txt",
        file_size=25,
        transfer_time=transfer_time,
        response_time=0.15
    )
