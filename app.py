from flask import Flask, jsonify, request, render_template
import requests
import pymysql


app = Flask(__name__)

# MySQL Configuration
db = pymysql.connect(host="localhost", user="admin", password="admin@123", database="cve_db")
cursor = db.cursor()

# Function to Fetch & Store CVE Data in MySQL
def fetch_and_store_cve():
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    start_index = 0
    results_per_page = 10  # Adjust as needed
    max_retries = 5  # Number of retries in case of failure

    while True:
        api_url = f"{base_url}?startIndex={start_index}&resultsPerPage={results_per_page}"
        
        for attempt in range(max_retries):
            try:
                response = requests.get(api_url, timeout=10)  # Add timeout for stability
                if response.status_code == 429:  # Too many requests
                    print(f"Rate limit hit. Retrying in 60 seconds... (Attempt {attempt+1}/{max_retries})")
                    time.sleep(60)  # Wait and retry
                    continue

                response.raise_for_status()  # Raise an error for 4xx/5xx responses
                data = response.json()

                if not data or "vulnerabilities" not in data:
                    print("Warning: API response is empty or invalid.")
                    return

                for item in data["vulnerabilities"]:
                    cve_id = item["cve"]["id"]
                    description = item["cve"]["descriptions"][0]["value"]
                    cvss_score = item["cve"]["metrics"].get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseScore", None)
                    published_date = item["cve"]["published"]
                    last_modified_date = item["cve"]["lastModified"]

                    cursor.execute("""
                        INSERT INTO cve_data (cve_id, description, cvss_score, published_date, last_modified_date)
                        VALUES (%s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                        description = VALUES(description), cvss_score = VALUES(cvss_score), 
                        last_modified_date = VALUES(last_modified_date)
                    """, (cve_id, description, cvss_score, published_date, last_modified_date))
                    db.commit()

                start_index += results_per_page
                break  # Exit retry loop if successful

            except requests.exceptions.RequestException as e:
                print(f"Error fetching data (Attempt {attempt+1}/{max_retries}): {e}")
                time.sleep(5)  # Wait before retrying
        
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
        "description": row[2], 
        "cvss_score": row[3], 
        "published_date": row[4], 
        "last_modified_date": row[5]
    } for row in data])
    
# @app.route('/cves/list')
# def cve_list():
#     return fetch_paginated_cves()

# API to Get a CVE by ID
@app.route("/cves/<cve_id>", methods=["GET"])
def get_cve_by_id(cve_id):
    cursor.execute("SELECT * FROM cve_data WHERE cve_id = %s", (cve_id,))
    row = cursor.fetchone()
    
    if row:
        return render_template("cve_detail.html", cve={
            "cve_id": row[1], 
            "description": row[2], 
            "cvss_score": row[3], 
            "published_date": row[4], 
            "last_modified_date": row[5]
        })
    
    return render_template("error.html", message="CVE Not Found"), 404

# Homepage - Displays CVE List with Pagination
@app.route("/cves/list")
def index():
    return fetch_paginated_cves()

# Function to Fetch Paginated CVE Data
def fetch_paginated_cves():
    # Pagination Variables
    page = request.args.get('page', 1, type=int)  # Default to page 1
    per_page = request.args.get('per_page', 10, type=int)  # Default per page

    # Sorting Variable
    sort_order = request.args.get('sort', 'desc')  # Default sorting by latest (descending)

    # Validate sorting order
    if sort_order not in ['asc', 'desc']:
        sort_order = 'desc'  

    # Calculate Offset
    offset = (page - 1) * per_page

    # Fetch CVE Data with Pagination
    cursor.execute(f"SELECT cve_id, description, cvss_score, published_date, last_modified_date FROM cve_data ORDER BY published_date {sort_order} LIMIT %s OFFSET %s", (per_page, offset))
    cve_records = cursor.fetchall()

    # Get Total Records Count
    cursor.execute("SELECT COUNT(*) FROM cve_data")
    total_records = cursor.fetchone()[0]

    # Calculate Total Pages
    total_pages = (total_records + per_page - 1) // per_page

    return render_template("index.html", cve_records=cve_records, page=page, per_page=per_page, total_pages=total_pages, total_records=total_records, sort_order=sort_order)

if __name__ == "__main__":
    # fetch_and_store_cve()  # Fetch data at startup
    app.run(debug=True)
