import os
import requests

def scan_file(file_path, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}

    try:
        with open(file_path, 'rb') as file:
            files = {'file': file}
            response = requests.post(url, files=files, params=params)
            response.raise_for_status()  # Raise an exception for HTTP errors
            return response.json()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

def get_scan_report(resource, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': resource}

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()  # Raise an exception for HTTP errors
        return response.json()
    except Exception as e:
        print(f"An error occurred: {e}")

def scan_files_in_folder(folder_path, api_key):
    if not os.path.isdir(folder_path):
        print("Folder not found.")
        return

    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        if os.path.isfile(file_path):
            print(f"Scanning file: {file_name}")
            scan_result = scan_file(file_path, api_key)
            if scan_result and 'resource' in scan_result:
                resource = scan_result['resource']
                print(f"File submitted for scanning. Resource: {resource}")

                # Check scan report
                report = get_scan_report(resource, api_key)
                if report:
                    if 'positives' in report:
                        positives = report['positives']
                        total = report['total']
                        print(f"Scan results: {positives}/{total} scanners detected the file as malicious.")
                    else:
                        print("Scan report not available yet. Try again later.")
                else:
                    print("Failed to retrieve scan report.")
            else:
                print("Failed to submit file for scanning.")

def main():
    api_key = input("Enter your VirusTotal API key: ")
    folder_path = input("Enter the path to the folder containing files to scan: ")

    if not api_key:
        print("API key is required.")
        return

    if not folder_path:
        print("Folder path is required.")
        return

    scan_files_in_folder(folder_path, api_key)

if __name__ == "__main__":
    main()
