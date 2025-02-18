from flask import Flask, jsonify, request, render_template
import requests
import pymysql
import time

app = Flask(__name__)

# MySQL Configuration
db = pymysql.connect(user="root", password="WAHEguru123@", database="cve_db", autocommit=True)
cursor = db.cursor()

def safe_float(value, default=0.0):
    """Convert value to float, return default if conversion fails."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default
# Function to Fetch & Store All CVE Data
def fetch_and_store_cve():
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    start_index = 0
    results_per_page = 2000
    max_retries = 5
    retry_delay = 5

    while True:
        api_url = f"{base_url}?startIndex={start_index}&resultsPerPage={results_per_page}"
        for attempt in range(max_retries):
            try:
                response = requests.get(api_url, timeout=30)
                if response.status_code == 429:
                    print(f"Rate limit hit. Retrying in 60 seconds... (Attempt {attempt+1}/{max_retries})")
                    time.sleep(60)
                    continue

                response.raise_for_status()
                data = response.json()

                if not data or "vulnerabilities" not in data:
                    print("No more CVE data available.")
                    return

                insert_data = []
                for item in data["vulnerabilities"]:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "N/A")
                    identifier = cve.get("sourceIdentifier", "N/A")
                    published_date = cve.get("published", "N/A")
                    last_modified_date = cve.get("lastModified", "N/A")
                    status = cve.get("vulnStatus", "N/A")

                    descriptions = {desc.get("lang", "N/A"): desc.get("value", "N/A") for desc in cve.get("descriptions", [])}
                    description = descriptions.get("en", descriptions.get("N/A", "N/A"))

                    cvss_metrics = cve.get("metrics", {}).get("cvssMetricV2", [{}])[0]
                    cvss_data = cvss_metrics.get("cvssData", {})

                    cvss_score = safe_float(cvss_data.get("baseScore"))
                    vector_string = cvss_data.get("vectorString", "N/A")
                    access_vector = cvss_data.get("accessVector", "N/A")
                    access_complexity = cvss_data.get("accessComplexity", "N/A")
                    authentication = cvss_data.get("authentication", "N/A")
                    confidentiality_impact = cvss_data.get("confidentialityImpact", "N/A")
                    integrity_impact = cvss_data.get("integrityImpact", "N/A")
                    availability_impact = cvss_data.get("availabilityImpact", "N/A")

                    severity = cvss_metrics.get("baseSeverity", "N/A")
                    exploitability_score = safe_float(cvss_metrics.get("exploitabilityScore"))
                    impact_score = safe_float(cvss_metrics.get("impactScore"))

                    configurations = cve.get("configurations", [])
                    vulnerable, criteria, match_criteria_id = None, "N/A", "N/A"
                    if configurations:
                        for config in configurations:
                            for node in config.get("nodes", []):
                                for cpe in node.get("cpeMatch", []):
                                    if cpe.get("vulnerable", False):
                                        vulnerable = 1 if cpe.get("vulnerable", False) else 0
                                        criteria = cpe.get("criteria", "N/A")
                                        match_criteria_id = cpe.get("matchCriteriaId", "N/A")
                                        break

                    insert_data.append((
                        cve_id, description, identifier, cvss_score, published_date, last_modified_date, 
                        status, severity, cvss_score, vector_string, access_vector, access_complexity, 
                        authentication, confidentiality_impact, integrity_impact, availability_impact, 
                        exploitability_score, impact_score, vulnerable, criteria, match_criteria_id
                    ))

                cursor.executemany("""
                    INSERT INTO cve_data (
                        cve_id, description, identifier, cvss_score, published_date, last_modified_date, 
                        status, severity, score, vector_string, access_vector, access_complexity, 
                        authentication, confidentiality_impact, integrity_impact, availability_impact, 
                        exploitability_score, impact_score, vulnerable, criteria, match_criteria_id
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    ON DUPLICATE KEY UPDATE 
                        description = VALUES(description), 
                        identifier = VALUES(identifier), 
                        cvss_score = VALUES(cvss_score), 
                        published_date = VALUES(published_date), 
                        last_modified_date = VALUES(last_modified_date), 
                        status = VALUES(status), 
                        severity = VALUES(severity), 
                        score = VALUES(score), 
                        vector_string = VALUES(vector_string), 
                        access_vector = VALUES(access_vector), 
                        access_complexity = VALUES(access_complexity), 
                        authentication = VALUES(authentication), 
                        confidentiality_impact = VALUES(confidentiality_impact), 
                        integrity_impact = VALUES(integrity_impact), 
                        availability_impact = VALUES(availability_impact), 
                        exploitability_score = VALUES(exploitability_score), 
                        impact_score = VALUES(impact_score), 
                        vulnerable = VALUES(vulnerable), 
                        criteria = VALUES(criteria), 
                        match_criteria_id = VALUES(match_criteria_id);
                """, insert_data)
                print(f"Inserted {len(insert_data)} records from index {start_index}")
                start_index += results_per_page
                break

            except requests.exceptions.RequestException as e:
                print(f"Error fetching data (Attempt {attempt+1}/{max_retries}): {e}")
                time.sleep(retry_delay)

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
        "status":row[6]
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
            "cve_id": row[0], 
            "discription": row[1], 
            "severity": row[7], 
            "score":row[8],
            "vector_string":row[9],
            "access_vector":row[10],
            "access_complexity":row[11],
            "authentication":row[12],
            "confidentiality_impact":row[13],
            "integrity_impact":row[14],
            "availability_impact":row[15],
            "exploitability_Score":row[16],
            "impact_score":row[17],
            "criteria":row[19],
            "match_criteria_id":row[20],
            "vulnerable":row[18],
            "published_date": row[4], 
            "last_modified_date": row[5],
            "status": row[6]
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
    cursor.execute(f"SELECT cve_id, identifier, cvss_score, published_date, last_modified_date,status FROM cve_data ORDER BY published_date {sort_order} LIMIT %s OFFSET %s", (per_page, offset))
    cve_records = cursor.fetchall()

    # Get Total Records Count
    cursor.execute("SELECT COUNT(*) FROM cve_data")
    total_records = cursor.fetchone()[0]

    # Calculate Total Pages
    total_pages = (total_records + per_page - 1) // per_page

    return render_template("index.html", cve_records=cve_records, page=page, per_page=per_page, total_pages=total_pages, total_records=total_records, sort_order=sort_order)

if __name__ == "__main__":
    #fetch_and_store_cve()  # Fetch data at startup
    app.run(debug=True)
