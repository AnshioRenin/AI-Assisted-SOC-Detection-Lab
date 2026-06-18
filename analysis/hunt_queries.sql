-- =====================================================================
-- hunt_queries.sql  -  Threat hunting over exported Wazuh alerts/events
-- =====================================================================
--
-- WHY SQL FOR HUNTING:
--   A SIEM dashboard is great for triggered alerts. Threat HUNTING means
--   proactively looking for suspicious patterns the rules did NOT alert on.
--   Loading events into SQLite lets you ask precise, repeatable questions.
--
-- HOW TO LOAD YOUR DATA (run in a terminal):
--   1. In Wazuh, export events to CSV (Discover > Save/Export), or pull from
--      the alerts.json archive at /var/ossec/logs/archives/.
--   2. Create the database and import:
--        sqlite3 hunt.db
--        .mode csv
--        .import events.csv events
--   3. Then run the queries below:  .read analysis/hunt_queries.sql
--
-- ASSUMED SCHEMA (adjust column names to match your export):
--   events(timestamp, agent_name, image, parent_image, command_line,
--          target_image, target_object, event_id, rule_id, rule_level,
--          mitre_id, user)
-- =====================================================================


-- 1) Volume by MITRE technique - what is this endpoint mostly doing?
SELECT mitre_id, COUNT(*) AS hits
FROM events
WHERE mitre_id IS NOT NULL AND mitre_id <> ''
GROUP BY mitre_id
ORDER BY hits DESC;


-- 2) Encoded / hidden PowerShell (T1059.001) - execution hunting
SELECT timestamp, agent_name, user, command_line
FROM events
WHERE image LIKE '%powershell.exe%'
  AND (command_line LIKE '%-enc%'
       OR command_line LIKE '%-encodedcommand%'
       OR command_line LIKE '%hidden%'
       OR command_line LIKE '%-nop%')
ORDER BY timestamp DESC;


-- 3) Suspicious parent-child chains - Office/script host spawning shells
--    (classic phishing/maldoc execution chain)
SELECT timestamp, agent_name, parent_image, image, command_line
FROM events
WHERE parent_image LIKE '%WINWORD.EXE%'
   OR parent_image LIKE '%EXCEL.EXE%'
   OR parent_image LIKE '%OUTLOOK.EXE%'
   OR parent_image LIKE '%wscript.exe%'
   OR parent_image LIKE '%mshta.exe%'
ORDER BY timestamp DESC;


-- 4) LSASS access (T1003) - credential dumping hunting
SELECT timestamp, agent_name, image AS accessing_process, target_image
FROM events
WHERE target_image LIKE '%lsass.exe%'
ORDER BY timestamp DESC;


-- 5) Registry Run key persistence (T1547.001)
SELECT timestamp, agent_name, target_object, image AS process
FROM events
WHERE target_object LIKE '%CurrentVersion\Run%'
   OR target_object LIKE '%CurrentVersion\RunOnce%'
ORDER BY timestamp DESC;


-- 6) Rare processes - "least frequency" hunting.
--    Processes that ran only once or twice are worth a look (LOLBins, droppers).
SELECT image, COUNT(*) AS times_seen
FROM events
WHERE image IS NOT NULL AND image <> ''
GROUP BY image
HAVING times_seen <= 2
ORDER BY times_seen ASC;


-- 7) High-severity alert timeline - what fired and when, worst first
SELECT timestamp, agent_name, rule_level, rule_id, mitre_id
FROM events
WHERE rule_level >= 10
ORDER BY rule_level DESC, timestamp DESC;


-- 8) Activity per user account - spot a compromised or unusual account
SELECT user, COUNT(*) AS events, MAX(rule_level) AS worst_level
FROM events
WHERE user IS NOT NULL AND user <> ''
GROUP BY user
ORDER BY worst_level DESC, events DESC;
