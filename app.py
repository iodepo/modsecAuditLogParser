import re
from flask import Flask, render_template, request, redirect

app = Flask(__name__)

def parse_modsec_log(log_content):
    """
    Robust parser that scans entire transaction blocks for patterns
    instead of relying on strict line-by-line structures.
    """
    entries = []

    # Split by the transaction start boundary (--ID-A--)
    # We ignore the very first split if it's empty
    # The regex captures the boundary so we can keep the ID
    chunks = re.split(r'(--[a-zA-Z0-9]+-A--)', log_content)

    current_entry = None

    for i in range(len(chunks)):
        chunk = chunks[i].strip()
        if not chunk:
            continue

        # Check if this chunk is a Boundary Marker
        header_match = re.match(r'--([a-zA-Z0-9]+)-A--', chunk)

        if header_match:
            # We found a new start.
            # 1. Save the previous entry if it exists
            if current_entry:
                # Final score calculation before saving
                max_score = max(current_entry['score_in'], current_entry['score_out'])
                # Fallback: if score is 0 but we found severity ratings, verify logic
                if max_score == 0 and current_entry['severity_points'] > 0:
                    max_score = current_entry['severity_points']

                current_entry['score'] = max_score
                entries.append(current_entry)

            # 2. Start a new entry
            current_entry = {
                'id': header_match.group(1),
                'timestamp': 'Unknown Time',
                'source_ip': 'Unknown',
                'dest_ip': 'Unknown',
                'method': 'Unknown',
                'request_uri': '',
                'user_agent': '',
                'messages': [],
                'score_in': 0,
                'score_out': 0,
                'score': 0,
                'severity_points': 0, # Backup counter
                'raw_request': ''
            }

        elif current_entry:
            # This chunk is the CONTENT of the transaction (Parts B, H, Z, etc.)
            # We treat the whole text block as one searchable string.

            # --- 1. Extract Headers (Timestamp & IPs) ---
            # Looks for: [25/Nov/2023:14:00:00 +0000] 1.2.3.4 1234 5.6.7.8 80
            if current_entry['source_ip'] == 'Unknown':
                header_data = re.search(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s?[+\-]\d{4})\].*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\d+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', chunk)
                if header_data:
                    current_entry['timestamp'] = header_data.group(1)
                    current_entry['source_ip'] = header_data.group(2)
                    current_entry['dest_ip'] = header_data.group(3)

            # --- 2. Extract Request Info (Method & URI) ---
            # We look for the Part B header and take the lines after it
            if f"--{current_entry['id']}-B--" in chunk:
                # Find the boundary, extract text until next boundary
                part_b_match = re.search(f"--{current_entry['id']}-B--\n(.*?)\n--{current_entry['id']}-", chunk, re.DOTALL)
                if part_b_match:
                    raw_req = part_b_match.group(1)
                    current_entry['raw_request'] = raw_req.strip()

                    # First line is usually: GET /path HTTP/1.1
                    first_line = raw_req.split('\n')[0].strip()
                    parts = first_line.split()
                    if len(parts) >= 2:
                        current_entry['method'] = parts[0]
                        current_entry['request_uri'] = parts[1]

                    # User Agent
                    ua_match = re.search(r'(?i)^User-Agent:\s*(.+)$', raw_req, re.MULTILINE)
                    if ua_match:
                        current_entry['user_agent'] = ua_match.group(1)

            # --- 3. Extract Messages & Severities ---
            # Find all lines starting with "Message:"
            msg_matches = re.findall(r'^Message:\s*(.+)$', chunk, re.MULTILINE)
            for msg in msg_matches:
                # Extract Rule ID
                id_match = re.search(r'\[id "(\d+)"\]', msg)
                rule_id = id_match.group(1) if id_match else "-"

                # Extract Severity
                sev_match = re.search(r'\[severity "(.*?)"\]', msg)
                severity = sev_match.group(1) if sev_match else "INFO"

                # Add to list
                current_entry['messages'].append({
                    'rule_id': rule_id,
                    'severity': severity,
                    'raw': msg
                })

                # Calculate "Backup Score" in case explicit score is missing
                sev_map = {'CRITICAL': 5, 'ERROR': 4, 'WARNING': 3, 'NOTICE': 2}
                current_entry['severity_points'] += sev_map.get(severity.upper(), 0)

                # CHECK FOR EMBEDDED SCORES (The specific issue you faced)
                # Matches: "matched 4 at TX:outbound_anomaly_score"
                embedded_score = re.search(r'matched\s+(\d+)\s+at\s+TX:(inbound|outbound)_anomaly_score', msg, re.IGNORECASE)
                if embedded_score:
                    score_val = int(embedded_score.group(1))
                    direction = embedded_score.group(2).lower()
                    if direction == 'inbound':
                        current_entry['score_in'] = max(current_entry['score_in'], score_val)
                    else:
                        current_entry['score_out'] = max(current_entry['score_out'], score_val)

            # --- 4. Extract Explicit Scores (Footer) ---
            # Flexible regex that handles "Score: 5" and "Score:5" and "Score:  5"
            in_score = re.search(r'Total Inbound Score:?\s*(\d+)', chunk)
            if in_score:
                current_entry['score_in'] = max(current_entry['score_in'], int(in_score.group(1)))

            out_score = re.search(r'Total Outbound Score:?\s*(\d+)', chunk)
            if out_score:
                current_entry['score_out'] = max(current_entry['score_out'], int(out_score.group(1)))

    # Append the final entry
    if current_entry:
        max_score = max(current_entry['score_in'], current_entry['score_out'])
        if max_score == 0 and current_entry['severity_points'] > 0:
            max_score = current_entry['severity_points']
        current_entry['score'] = max_score
        entries.append(current_entry)

    return entries

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'logfile' not in request.files:
            return redirect(request.url)

        file = request.files['logfile']
        if file.filename == '':
            return redirect(request.url)

        if file:
            # Use 'replace' to handle weird characters in binary logs
            content = file.read().decode('utf-8', errors='replace')
            parsed_data = parse_modsec_log(content)

            total_count = len(parsed_data)
            # Limit to last 500 to prevent MacOS crashing
            if total_count > 500:
                parsed_data = parsed_data[-500:]

            return render_template('report.html',
                                   entries=parsed_data,
                                   count=total_count,
                                   shown=len(parsed_data))

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)