# Google Indexing API URL Submission

This repository contains a Python project for automated submission of URLs to the Google Indexing API. It includes both a GUI application and a command-line tool, allowing you to easily index pages with minimal manual effort. The project also implements a simple local database to prevent re-indexing of URLs that have already been processed.

> **Note:** With a default configured service account, you can index up to 200 pages per day.

---

## Features

- **GUI Application:**  
  A user-friendly interface (built with Tkinter) that allows you to select JSON key files, paste a list of URLs, and monitor the indexing process in real time.
  
- **Command-Line Tool:**  
  Submit URLs in batch mode using a terminal-based script with customizable notification types (`URL_UPDATED` or `URL_DELETED`).

- **Local Database:**  
  Tracks indexed URLs to avoid duplicates when using the local storage option.

- **Batch Processing:**  
  Automatically splits URL submissions into manageable batches (100 URLs per batch) for efficient processing.

---

## Getting Started

### Prerequisites

- Python 3.6 or higher  
- Required Python packages (see [requirements.txt](requirements.txt)):
  - `google-auth`
  - `google-api-python-client`
  - `tkinter` (usually bundled with Python. Needs only for GUI)
  - Others as specified in the requirements file

### Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/keklick1337/googlefastindex.git
   cd googlefastindex
   ```

2. **Install Dependencies**

   Use pip to install the required packages:

   ```bash
   pip install -r requirements.txt
   ```

---

## Google API Setup

Before you can use the scripts, you need to set up access to the Google Indexing API:

1. **Create a Fresh Google Account**  
   (If necessary, register a new account dedicated to managing API access.)

2. **Create a Google Cloud Project**  
   - Log in to the [Google Cloud Console](https://console.cloud.google.com/).
   - Create a new project.

3. **Enable the Indexing API**  
   - Open the [Indexing API Dashboard](https://console.cloud.google.com/apis/api/indexing.googleapis.com/metrics).
   - Enable the Indexing API for your project.

4. **Create a Service Account and Generate a JSON Key**  
   - Go to the [Service Accounts page](https://console.cloud.google.com/iam-admin/serviceaccounts).
   - Create a new service account.
   - Generate and download the JSON key file for the service account.

5. **Add the Service Account to Google Search Console**  
   - Visit the [Google Search Console Users](https://search.google.com/search-console/users) page.
   - Add the service account (via its service email) as an owner to your website property.

---

## Usage

### GUI Application

The graphical interface makes it easy to manage URL submissions:

1. **Run the GUI Script**

   ```bash
   python search_index_gui.py
   ```

2. **Select JSON Key Files**  
   Click on **"Select JSON Key Files"** and choose one or more JSON files containing your service account credentials.

3. **Input URLs**  
   Paste or type the URLs you want to index into the provided text area. The application will detect and count the URLs automatically.

4. **Configure Options**  
   - Enable the local database option to prevent re-indexing of previously submitted URLs.
   - Review the count of URLs and JSON keys before submitting.

5. **Submit URLs**  
   Click the **"Submit URLs"** button to start the indexing process. The GUI will process the URLs in batches, update the progress bar, and display logs for each action.

6. **Monitor Logs and Results**  
   Use the results tab and log area to monitor successful submissions and errors.

### Command-Line Tool

For users who prefer working via the terminal, the CLI script offers a streamlined experience:

1. **Prepare a URL File**  
   Create a text file (e.g., `urls.txt`) listing one URL per line.

2. **Run the CLI Script**

   ```bash
   python search_index.py path/to/your/json_key.json path/to/your/urls.txt --type URL_UPDATED
   ```

   **Parameters:**
   - `path/to/your/json_key.json`: Path to your service account JSON key file.
   - `path/to/your/urls.txt`: Path to the text file containing the URLs.
   - `--type`: (Optional) Notification type, either `URL_UPDATED` or `URL_DELETED` (defaults to `URL_UPDATED`).

---

## Limitations

- **Daily Quota:**  
  Due to API limitations, this tool is designed to index up to 200 URLs per day.
- **Batch Size:**  
  URLs are processed in batches (with a default size of 100 per batch) to optimize API calls.

---

## Contributing

Contributions, bug reports, and feature requests are welcome!  
Feel free to open issues or submit pull requests on this repository.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Contact

Created by [keklick1337](https://github.com/keklick1337).  
For questions, support, or contributions, please create an issue in this repository.