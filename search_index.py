import os
import sys
import argparse
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import BatchHttpRequest

def main():
    parser = argparse.ArgumentParser(description='Submit URLs to Google Indexing API')
    parser.add_argument('json_key', help='Path to the service account JSON key file')
    parser.add_argument('urls_file', help='Path to the file containing URLs, one per line')
    parser.add_argument('--type', choices=['URL_UPDATED', 'URL_DELETED'], default='URL_UPDATED', help='Type of notification')
    args = parser.parse_args()

    JSON_KEY_FILE = args.json_key
    URLS_FILE = args.urls_file
    NOTIFICATION_TYPE = args.type

    if not os.path.exists(JSON_KEY_FILE):
        print(f'JSON key file not found: {JSON_KEY_FILE}')
        sys.exit(1)

    if not os.path.exists(URLS_FILE):
        print(f'URLs file not found: {URLS_FILE}')
        sys.exit(1)

    SCOPES = ['https://www.googleapis.com/auth/indexing']
    credentials = service_account.Credentials.from_service_account_file(
        JSON_KEY_FILE, scopes=SCOPES)

    service = build('indexing', 'v3', credentials=credentials)

    def callback(request_id, response, exception):
        if exception:
            print(f'Failed to submit {request_id}: {exception}')
        else:
            print(f'Successfully submitted {request_id}')

    def read_urls(file_path, chunk_size=100):
        with open(file_path, 'r') as f:
            chunk = []
            for line in f:
                url = line.strip()
                if url:
                    chunk.append(url)
                    if len(chunk) == chunk_size:
                        yield chunk
                        chunk = []
            if chunk:
                yield chunk

    for i, chunk in enumerate(read_urls(URLS_FILE)):
        batch = service.new_batch_http_request(callback=callback)
        for url in chunk:
            request = service.urlNotifications().publish(body={
                'url': url,
                'type': NOTIFICATION_TYPE
            })
            batch.add(request, request_id=url)
        try:
            batch.execute()
            print(f'Batch {i+1} executed.')
        except Exception as e:
            print(f'Error executing batch {i+1}: {e}')

    print('All batches processed.')

if __name__ == '__main__':
    main()