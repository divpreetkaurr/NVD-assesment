**CVE Data Fetcher and Viewer**
This project provides a Flask web application for fetching, storing, and displaying CVE (Common Vulnerabilities and Exposures) data. It interacts with the National Vulnerability Database (NVD) API to retrieve CVE data, stores it in a MySQL database, and presents it via a web interface with pagination and detailed views.

**Features**
-Fetch and store CVE data from the NVD API.
-Paginated view of CVE data with options to sort by date.
-Detailed view of each CVE by ID.
-RESTful API to access CVE data.
-MySQL integration to store and query CVE information.
-User-friendly web interface with dynamic sorting and pagination.

**Setup Instructions**
**Prerequisites-**
-Python 3.x
-MySQL
-Flask
-Requests
-PyMySQL
**Installation**
Clone this repository:

git clone https://github.com/divpreetkaurr/NVD_assesment.git
**Install dependencies:**
pip install -r requirements.txt

Set up your MySQL database:

-Create a database named cve_db in MySQL.
-Create a table for storing CVE data:

CREATE TABLE cve_data (
    cve_id VARCHAR(255) PRIMARY KEY,
    description TEXT,
    identifier VARCHAR(255),
    cvss_score FLOAT,
    published_date DATETIME,
    last_modified_date DATETIME,
    status VARCHAR(50),
    severity VARCHAR(50),
    score FLOAT,
    vector_string TEXT,
    access_vector VARCHAR(50),
    access_complexity VARCHAR(50),
    authentication VARCHAR(50),
    confidentiality_impact VARCHAR(50),
    integrity_impact VARCHAR(50),
    availability_impact VARCHAR(50),
    exploitability_score FLOAT,
    impact_score FLOAT,
    vulnerable INT,
    criteria TEXT,
    match_criteria_id VARCHAR(50)
);


--Update MySQL credentials in app.py:
db = pymysql.connect(user="root", password="yourpassword", database="cve_db", autocommit=True)


--Run the application:

python app.py

**API Endpoints**
GET /api/cves: Fetch all CVE data from the database.
GET /cves/<cve_id>: Fetch detailed information for a specific CVE by ID.
**Web Interface**
The homepage displays a paginated list of CVEs with options to sort by the published date.
Clicking on a CVE ID provides detailed information about the CVE.
**Pagination and Sorting**
The index.html page supports pagination and sorting by published date (ascending or descending).
The number of records per page can be adjusted using a dropdown.
**Error Handling**
If a CVE ID is not found, a custom error page is displayed.
**How It Works**
The fetch_and_store_cve() function fetches CVE data from the NVD API and stores it in the MySQL database.
The Flask application serves the CVE data via a web interface with pagination and sorting.
The API provides access to all CVE data and individual CVEs by their ID.
**Troubleshooting**
If you encounter issues with fetching CVE data, ensure that your API key (if required) is valid and that your MySQL database is properly configured.
For rate limiting from the NVD API, the application retries up to 5 times with a delay of 5 seconds.
Feel free to fork this repository and submit pull requests. If you find any bugs or have suggestions for improvements, please open an issue.


![image](https://github.com/user-attachments/assets/1b99aa44-01b7-4e01-8267-c942dfdf6ca6)
![image](https://github.com/user-attachments/assets/234ff776-3780-46e7-bfa5-9e4bb5346c25)
![image](https://github.com/user-attachments/assets/bbe14a59-88e7-419b-8127-b93945f0ca18)
