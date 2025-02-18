from flask import Flask, jsonify, request, render_template
import requests
import pymysql
import time

app = Flask(__name__)

# MySQL Configuration
db = pymysql.connect(user="root", password="WAHEguru123@", database="cve_db", autocommit=True)
cursor = db.cursor()

# Function to Fetch & Store All CVE Data
def fetch_and_store_all_cve():
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    start_index = 0
    results_per_page = 2000  # Fetch more results per request
    max_retries = 5  

    while True:
        api_url = f"{base_url}?startIndex={start_index}&resultsPerPage={results_per_page}"
        for attempt in range(max_retries):
            try:
                response = requests.get(api_url, timeout=10)  
                if response.status_code == 429:  
                    print(f"Rate limit hit. Retrying in 60 seconds... (Attempt {attempt+1}/{max_retries})")
                    time.sleep(60)  
                    continue

                response.raise_for_status()
                data = response.json()

                if not data or "vulnerabilities" not in data:
                    print("No more CVE data available.")
                    return  

                # Prepare Bulk Insert Data
                insert_data = []
                for item in data["vulnerabilities"]:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "N/A")
                    identifier = cve.get("sourceIdentifier", "N/A")
                    cvss_score = cve.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseScore", None)
                    published_date = cve.get("published", "N/A")
                    last_modified_date = cve.get("lastModified", "N/A")
                    status = cve.get("vulnStatus", "N/A")

                    insert_data.append((cve_id, identifier, cvss_score, published_date, last_modified_date, status))

                # Insert data into MySQL
                cursor.executemany("""
                    INSERT INTO cve_data (cve_id, identifier, cvss_score, published_date, last_modified_date, status)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                    identifier = VALUES(identifier), cvss_score = VALUES(cvss_score), 
                    last_modified_date = VALUES(last_modified_date), status = VALUES(status)
                """, insert_data)

                print(f"Inserted {len(insert_data)} records from index {start_index}")
                start_index += results_per_page
                break  

            except requests.exceptions.RequestException as e:
                print(f"Error fetching data (Attempt {attempt+1}/{max_retries}): {e}")
                time.sleep(5)  

        else:
            print("Max retries reached. Exiting fetch process.")
            return

# API to Get All CVEs
@app.route("/api/cves", methods=["GET"])
def get_cves():
    cursor.execute("SELECT * FROM cve_data")
    data = cursor.fetchall()
    return jsonify([{
        "cve_id": row[1], 
        "identifier": row[2], 
        "cvss_score": row[3], 
        "published_date": row[4], 
        "last_modified_date": row[5],
        "status": row[6]
    } for row in data])

# API to Get a CVE by ID
@app.route("/cves/<cve_id>", methods=["GET"])
def get_cve_by_id(cve_id):
    cursor.execute("SELECT * FROM cve_data WHERE cve_id = %s", (cve_id,))
    row = cursor.fetchone()
    
    if row:
        return render_template("cve_detail.html", cve={
            "cve_id": row[0], 
            "identifier": row[1], 
            "cvss_score": row[2], 
            "published_date": row[3], 
            "last_modified_date": row[4],
            "status": row[5]
        })
    
    return render_template("error.html", message="CVE Not Found"), 404

# Homepage - Displays CVE List with Pagination
@app.route("/cves/list")
def index():
    return fetch_paginated_cves()

# Function to Fetch Paginated CVE Data
def fetch_paginated_cves():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    sort_order = request.args.get('sort', 'desc')

    if sort_order not in ['asc', 'desc']:
        sort_order = 'desc'  

    offset = (page - 1) * per_page

    cursor.execute(f"""
        SELECT cve_id, identifier, cvss_score, published_date, last_modified_date, status 
        FROM cve_data ORDER BY published_date {sort_order} LIMIT %s OFFSET %s
    """, (per_page, offset))
    cve_records = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM cve_data")
    total_records = cursor.fetchone()[0]
    total_pages = (total_records + per_page - 1) // per_page

    return render_template("index.html", cve_records=cve_records, page=page, per_page=per_page, total_pages=total_pages, total_records=total_records, sort_order=sort_order)

if __name__ == "__main__":
    #fetch_and_store_all_cve()  # Fetch all CVE data at startup
    app.run(debug=True)
