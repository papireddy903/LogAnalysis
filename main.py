from collections import Counter 
import re 
from typing import List, Dict 
import csv 
import logging 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class LogFileAnalyzer:

    def __init__(self, file_path: str, failed_login_threshold: int = 10)->None:
         """
         Initialize the Log File Analyzer class.

         Args: 
         :param file_path: Path to the log file to analyze.
         :param failed_login_threshold: Threshold for the number of failed login attempts to be considered suspicious.
         
         """
         self.file_path:str = file_path 
         self.failed_login_threshold:int = failed_login_threshold 
         self.log_data: Dict[str, Counter] = self._parseLogFile()  # Parse the log file when the object is initialized

    def _parseLogFile(self) -> Dict[str, Counter]:

        """
        Parse the log file to extract relevant data: IP Addresses, endpoints, and failed login attempts.

        Returns a dictionary containing counts of IP Addresses, endpoints, and failed logins.
        """
        
        ip_addresses: List[str] = [] 
        endpoints: List[str] = []
        failed_logins: List[str] = [] 

        try:
            with open(self.file_path, 'r') as log_file:  # Open the log file in read mode
                for line in log_file:  # Read each line of the log file
                    # Match IP addresses using regex
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip_addresses.append(ip_match.group(1))  # Append matched IP address to list

                    # Match endpoint paths using regex
                    endpoint_match = re.search(r'"[A-Z]+ (/[^\s]*)', line)
                    if endpoint_match:
                        endpoints.append(endpoint_match.group(1))   # Append matched endpoint path to list 


                    # Detect failed logins based on error message or HTTP status 401
                    if 'Invalid credentials' in line or ' 401 ' in line:
                        failed_logins.append(ip_match.group(1) if ip_match else 'Anonymous')   # Append IP of failed login or 'Anonymous' if no IP found


        # Handle possible file-related errors     
        except FileNotFoundError as e:
            logging.error(f"Error: Log file '{self.file_path} not found.")
            raise 

        except PermissionError as e:
            logging.error("Error: Permission denied for file '{self.file_path}'.")
            raise 
        
        except IOError as e:
            logging.error(f"Error: An IOError occurred while reading the file '{self.file_path}'.")
        
        # Return collected log data in the form of counters for each category
        return {
            'ip_counts': Counter(ip_addresses),
            'endpoint_counts':Counter(endpoints),
            'failed_logins':Counter(failed_logins)
        }


    def displayReport(self) -> None:
        """
        Display a summary of the log analysis:
        - List of IP addresses with their respective request count
        - Most frequently accessed endpoint
        - Suspicious activity based on failed login attempts

        """
        print("--- IP Address Requests ---")
        print("IP Address\t\t\t\tRequest Count")

        # Display the top IP addresses sorted by request count in descending order
        for ip, count in sorted(self.log_data['ip_counts'].items(), key = lambda x : x[1] , reverse=True):
            print(f"{ip}\t\t\t\t{count}")
        print("\n")

        print("--- Most Frequently Accessed Endpoint ---")
        # print(self.log_data['endpoint_counts'])
        most_accessed = max(self.log_data['endpoint_counts'].items(), key = lambda x : x[1]) # Find the endpoint with the highest access count
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)\n")

        print("--- Suspicious Activity Detected ---")
        print("IP Address\t\t\t\tFailed Login Attempts")

        # Filter suspicious logins based on the threshold value
        suspicious_logins: Dict[str, int] = {ip:count for ip,count in self.log_data['failed_logins'].items() if count > self.failed_login_threshold}

        # If there are any suspicious logins, print them
        if suspicious_logins:
            for ip, count in suspicious_logins.items():
                print(f"{ip}\t\t\t\t{count}")
        else:
            print("No suspicious login activities detected.")    # If no suspicious logins, display this message


    def saveResultsToCSV(self)->None:
        """
        Save the analysis results into a CSV file, making it easy to view and share.
        - Requests per IP
        - Most accessed endpoint
        - Suspicious logins
        """
        file_name = "log_analysis_results.csv"   # Define the output CSV file name


        with open(file_name, 'w', newline='') as output_file:
            csv_writer = csv.writer(output_file)   # Create a CSV writer object

            # Write the IP address counts
            csv_writer.writerow(['Requests per IP'])
            csv_writer.writerow(['IP Address', 'Request Count']) 
            for ip, count in sorted(self.log_data['ip_counts'].items(), key = lambda x : x[1], reverse=True):
                csv_writer.writerow([ip, count]) 

            csv_writer.writerow([])  # Add an empty row for separation

            # Write the most accessed endpoint
            csv_writer.writerow(['Most Accessed Endpoint'])
            most_accessed = max(self.log_data['endpoint_counts'].items(), key=lambda x: x[1])
            csv_writer.writerow(['Endpoint', 'Access Count'])
            csv_writer.writerow([most_accessed[0], most_accessed[1]])
            
            csv_writer.writerow([])   # Add an empty row for separation

            # Write the suspicious login attempts 
            suspicious_ips: Dict[str, int] = {
                ip: count for ip, count in self.log_data['failed_logins'].items() 
                if count > self.failed_login_threshold
            }
            csv_writer.writerow(['Suspicious Activity Detected'])
            csv_writer.writerow(['IP Address', 'Failed Login Count'])
            if suspicious_ips:
                for ip, count in suspicious_ips.items():
                    csv_writer.writerow([ip, count])
            else:
                csv_writer.writerow(['No suspicious login activities detected.']) # If no suspicious logins, save this message


        



def main():
    log_file = "sample.log"  # The log file to analyze
    failed_login_limit = 5 # Adjust threshold as needed

    analyzer = LogFileAnalyzer(log_file, failed_login_limit)  # Create an instance of LogFileAnalyzer

    analyzer.displayReport()  # Display the analysis report

    analyzer.saveResultsToCSV()  # Save the analysis results to CSV

if __name__ == "__main__":
    main()   # Run the main function when the script is executed