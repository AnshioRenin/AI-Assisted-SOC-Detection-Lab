-- hunt_queries.sql
-- Threat-hunting queries for the lab. Workflow:
--   1. Export your Sysmon/Wazuh events to CSV.
--   2. Load into SQLite:  sqlite3 lab.db
--        .mode csv
--        .import events.csv events
--   3. Run these queries (and write your own). Save interesting results for the README.
--
-- Assumes a table `events` with columns roughly like:
--   timestamp, agent, event_id, image, command_line, parent_image,
--   target_image, dest_ip, dest_port, mitre_id

-- 1) Volume of events per ATT&CK technique (where you have coverage / noise)
SELECT mitre_id, COUNT(*) AS hits
FROM events
WHERE mitre_id IS NOT NULL AND mitre_id <> ''
GROUP BY mitre_id
ORDER BY hits DESC;

-- 2) Processes that made outbound network connections (possible C2 / exfil)
SELECT image, dest_ip, dest_port, COUNT(*) AS conns
FROM events
WHERE dest_ip IS NOT NULL AND dest_ip <> ''
GROUP BY image, dest_ip, dest_port
ORDER BY conns DESC
LIMIT 25;

-- 3) Rare parent -> child process pairs (anomaly hunting:
--    e.g. winword.exe spawning powershell.exe is suspicious)
SELECT parent_image, image, COUNT(*) AS times_seen
FROM events
WHERE image IS NOT NULL
GROUP BY parent_image, image
HAVING times_seen <= 3        -- rare pairs are more interesting
ORDER BY times_seen ASC;

-- 4) Encoded / suspicious PowerShell command lines
SELECT timestamp, agent, command_line
FROM events
WHERE LOWER(command_line) LIKE '%-enc%'
   OR LOWER(command_line) LIKE '%-encodedcommand%'
   OR LOWER(command_line) LIKE '%downloadstring%';

-- 5) Any process touching LSASS (credential-dumping indicator, T1003)
SELECT timestamp, agent, image AS accessor, target_image
FROM events
WHERE LOWER(target_image) LIKE '%lsass.exe%';
