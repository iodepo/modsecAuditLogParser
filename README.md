# modsecAuditLogParser

ModSecurity creates a monster of an audit log file, very hard to read, very handy to find out what is going on.

They are notoriously difficult to read because they use a multi-part format (Parts A through Z) for every single request.

This parser gives you a simple overview of what is going on.

The complete parser runs on your local machine and is not intended to run on a server (for the time being).

## setup and run

How to run it

- you will need **python3** and **pip3** to run this
- clone the repository on your computer, typically in the dir **modsecAuditLogParser**
- go to the install directory
```
cd modsecAuditLogParser
```
- install the requirements
```
pip3 install -r requirements.txt
```
- run the application
```
python3 app.py
```
- surf to **http://127.0.0.1:5000**
- load your modsec_audit.log file and click on '**Analyze Logs**'

## file structure

your file structure should look like this


- modsecAuditLogParser 
  - app.py
  - requirements.txt
  - testModSecAudit.log     <--- test file, can be replace with your own
  - README.md               <--- this file
  - templates/ 
    - index.html            <--- upload page
    - report.html           <--- dashboard page


