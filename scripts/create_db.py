import os
import subprocess

pg_bin = r'c:\Users\DELL\OneDrive\Documents\Network-Intrusion-Detection-Major-Project\tools\pgsql\bin'
psql_exe = os.path.join(pg_bin, 'psql.exe')

sql_statements = [
    'CREATE DATABASE "NIDS";',
    'CREATE DATABASE nids;'
]

env = os.environ.copy()
env['PGPASSWORD'] = os.environ.get('POSTGRES_PASSWORD', os.environ.get('PGPASSWORD', ''))

for stmt in sql_statements:
    res = subprocess.run([psql_exe, '-U', 'postgres', '-p', '5432', '-d', 'postgres', '-c', stmt], env=env, capture_output=True, text=True)
    print(f"Executed: {stmt}\nStdout: {res.stdout.strip()}\nStderr: {res.stderr.strip()}\n")
