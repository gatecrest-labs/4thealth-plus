'use strict';

(function () {

// Each section has an optional `tab` key that must appear in window._helpAllowedTabs
// for the section to be shown. Sections with no `tab` are always visible.
const SECTIONS = [
  {
    id:    'overview',
    label: 'Overview',
    html: `
<h3>What is 4THealth+?</h3>
<p>4THealth+ is a read-only monitoring dashboard for your Fortinet infrastructure. It connects to FortiManager's API and displays live health data — no configuration changes are ever made to any device.</p>
<h3>Navigation</h3>
<ul>
  <li><strong>Dashboard</strong> — live health cards for FortiManager, FortiAnalyzer, and FortiCollector appliances.</li>
  <li><strong>Firewalls</strong> — browse managed FortiGate devices by ADOM, search by name or IP, and drill into full device details.</li>
  <li><strong>Device Versions</strong> — firmware version distribution across all devices in an ADOM.</li>
  <li><strong>Rule Review</strong> — policy viewer with full-text search and exports, plus automated hygiene checks on a selected package.</li>
  <li><strong>Device Review</strong> — per-device interface audit showing which management protocols (HTTP, Telnet, HTTPS, SSH, etc.) are enabled, with insecure protocols highlighted red.</li>
  <li><strong>Rule Validation</strong> — evaluate whether proposed flows are already permitted or need new/modified rules, with an optional AI Assist mode.</li>
  <li><strong>Zone Policy</strong> — browse and query your network segmentation policy database.</li>
  <li><strong>Config-Delta</strong> — see exactly which FortiOS CLI lines will change on the next install to a device, before it happens.</li>
  <li><strong>Map (Beta)</strong> — interactive geographic map of all managed FortiGate devices, colour-coded by ADOM with zoom-based clustering.</li>
</ul>
<h3>AI Assist</h3>
<p>Several tabs offer an optional AI Assist mode — Rule Validation, Device Review, Config-Delta, and Rule Review's Hygiene Analysis — plus an AI trend summary on the Admin page. All are off by default and gated by a single <strong>Admin → AI Assist</strong> toggle. In every case the AI only explains an already-computed result; it never decides a verdict, a check outcome, or a trend by itself — those are always computed deterministically first.</p>
<h3>Status Colours</h3>
<div class="help-status-list">
  <span class="status-dot green"></span> <span><strong>Green</strong> — device is reachable and all metrics are within normal thresholds.</span>
  <span class="status-dot yellow"></span> <span><strong>Yellow</strong> — device is reachable but CPU or memory is elevated (warn threshold).</span>
  <span class="status-dot red"></span> <span><strong>Red</strong> — device is unreachable, authentication failed, or a critical threshold is exceeded.</span>
  <span class="status-dot"></span> <span><strong>Grey</strong> — status unknown or not yet polled.</span>
</div>
<h3>Light / Dark Mode</h3>
<p>Click the <strong>☽ / ☀</strong> button in the top-right corner to toggle themes. Your preference is saved in the browser.</p>
`
  },
  {
    id:    'dashboard',
    label: 'Dashboard',
    html: `
<h3>Infrastructure Health Dashboard</h3>
<p>The dashboard shows one card per monitored appliance: <strong>FortiManager</strong> (primary &amp; secondary), <strong>FortiAnalyzer</strong> (primary &amp; secondary), and <strong>FortiCollector</strong> (#1 &amp; #2).</p>
<h3>Card Layout</h3>
<ul>
  <li>The <strong>coloured stripe</strong> on the left edge shows overall health (green / yellow / red).</li>
  <li>The <strong>left block</strong> shows the appliance label and its IP address.</li>
  <li>The <strong>right block</strong> shows: Hostname, Firmware Version, Serial Number, HA Mode / Role, and CPU &amp; Memory usage bars.</li>
</ul>
<h3>CPU &amp; Memory Bars</h3>
<ul>
  <li>Green bar — usage is normal.</li>
  <li>Yellow bar — usage has crossed the warn threshold (default: CPU 70%, Memory 75%).</li>
  <li>Red bar — usage has crossed the critical threshold (default: CPU 90%, Memory 90%).</li>
</ul>
<h3>Refreshing Data</h3>
<ul>
  <li>Click <strong>↺ Refresh</strong> to fetch fresh data immediately.</li>
  <li>Use the <strong>auto-refresh dropdown</strong> to set an automatic refresh interval (1 / 5 / 10 / 15 minutes). Default is every 5 minutes.</li>
  <li>The <em>Updated HH:MM:SS</em> timestamp below the title shows when data was last fetched.</li>
</ul>
<h3>Error Cards</h3>
<p>If an appliance is unreachable the card turns red and shows the error message (e.g. <em>Authentication failed</em> or a network timeout). This does not affect the other cards.</p>
`
  },
  {
    id:    'firewalls',
    label: 'Firewalls',
    html: `
<h3>Firewall Browser</h3>
<p>Browse all managed FortiGate devices registered in FortiManager, organised by ADOM.</p>
<h3>Selecting an ADOM</h3>
<p>Choose an ADOM from the dropdown. The device table loads automatically. Use auto-refresh to keep it current while you watch the screen.</p>
<h3>Search</h3>
<p>Type a device name or IP address in the search bar at the top and press <strong>Enter</strong> or click <strong>Search</strong>. Results are returned across <em>all</em> ADOMs simultaneously. Click <strong>Details</strong> in the result row to open the device detail panel.</p>
<p>You can also reach this tab directly from the Map — clicking <strong>View Details →</strong> on a device popup pre-fills the search and opens the device detail panel automatically.</p>
<h3>Device Table</h3>
<ul>
  <li>The <strong>status dot</strong> reflects FortiManager's connection state for each device (not live CPU/memory).</li>
  <li>Use the <strong>per-page selector</strong> (10 / 25 / 50 / 100) and pagination buttons to navigate large lists.</li>
  <li>Click <strong>Details</strong> on any row to open the full device health panel.</li>
</ul>
<h3>Device Detail Panel</h3>
<p>The detail panel fetches live data from FortiManager's proxy API and shows:</p>
<ul>
  <li><strong>System info</strong> — Mgmt IP, Platform, Version, Serial, Uptime, CPU %, Memory %, HA Mode.</li>
  <li><strong>Interfaces</strong> — admin status, link state, IP address, speed, RX/TX errors.</li>
  <li><strong>IPv4 Routes</strong> — full routing table with filter, page-size selector, and pagination.</li>
  <li><strong>BGP Neighbors</strong> — neighbour IP, AS, state, up/down timer, message counters.</li>
  <li><strong>OSPF Neighbors</strong> — router ID, state, interface, dead time.</li>
  <li><strong>IPsec Tunnels</strong> — tunnel name, remote gateway, SA status, uptime.</li>
</ul>
<p>Close the panel by clicking <strong>✕</strong>, clicking outside it, or pressing <strong>Escape</strong>.</p>
`
  },
  {
    id:    'versions',
    label: 'Device Versions',
    html: `
<h3>Device Version Report</h3>
<p>Two views: an <strong>All ADOMs</strong> chart at the top that covers every managed device, and a <strong>per-ADOM</strong> chart below that you select from the dropdown.</p>

<h3>All ADOMs Chart</h3>
<p>Shows firmware distribution across every ADOM in a single chart. Loaded from a background cache that builds at startup and refreshes every 30 minutes — the chart appears instantly without waiting for a live sweep.</p>
<ul>
  <li>A status line above the chart shows when the cache was last updated (e.g. <em>Last updated: 4m ago</em>). A spinner indicates the cache is still warming.</li>
  <li>Click <strong>↻ Refresh</strong> (next to the status line or the page-level button) to trigger an immediate background refresh.</li>
</ul>

<h3>Drilling into a Version (All ADOMs)</h3>
<ul>
  <li><strong>Click any version bar</strong> in the All ADOMs chart to expand a detail panel below it listing every firewall on that version, including the ADOM each device belongs to.</li>
  <li>Click the same bar again, or the <strong>✕ Close</strong> button in the detail panel, to collapse it.</li>
  <li>The detail panel supports <strong>pagination</strong> (10 / 25 / 50 per page, <code>&laquo; &lsaquo; … &rsaquo; &raquo;</code> controls) for large version groups.</li>
  <li>Export the full list using <strong>↡ CSV</strong>, <strong>↡ JSON</strong>, or <strong>↡ PDF</strong>. All exports include every matching device, not just the current page.</li>
</ul>

<h3>Per-ADOM Chart</h3>
<p>Select an ADOM from the dropdown to load its version breakdown.</p>
<ul>
  <li>Each row shows a firmware version, a proportional bar, the device count, and the percentage.</li>
  <li>Versions are sorted newest-first; <em>unknown</em> appears at the bottom.</li>
  <li><strong>Click any row</strong> to filter the device table below to only that version. Click the same row again, or <strong>✕ Clear filter</strong>, to show all versions.</li>
  <li>Click <strong>✕ Close</strong> (next to the Refresh button) to clear the ADOM selection and return the page to its original state.</li>
</ul>

<h3>Per-ADOM Device Table</h3>
<ul>
  <li>Shows Name, IP, Platform, Version, and Serial for the current filter selection.</li>
  <li>Use the <strong>per-page selector</strong> (10 / 20 / 50) and <strong>pagination buttons</strong> to navigate large device lists.</li>
  <li><strong>↡ CSV</strong> and <strong>↡ JSON</strong> export all devices matching the current version filter.</li>
</ul>
`
  },
  {
    id:    'hygiene',
    label: 'Rule Review',
    tab:   'rule_hygiene',
    html: `
<h3>Rule Review</h3>
<p>Four sections on this page: <strong>Policy Rules</strong>, <strong>Object Lookup</strong>, <strong>Interface Lookup</strong>, <strong>NAT Lookup</strong>, and <strong>Hygiene Analysis</strong>. Each has its own ADOM selector and works independently.</p>
<h3>Policy Rules</h3>
<p>Select an ADOM and Policy Package — the full rule table loads automatically.</p>
<ul>
  <li><strong>Search</strong> — full-text search across name, ID, comment, source, destination, service, and interface. Toggle <strong>Regex</strong> for regular expression matching.</li>
  <li><strong>Field filter</strong> — restrict the search to a single column (Name, Comment, Source, etc.).</li>
  <li><strong>Object expansion</strong> — click the triangle next to any address group or service group to see its members inline.</li>
  <li><strong>Page size</strong> — 10 / 25 / 50 / 100 rows, with <code>&lt;&lt; &lt; … &gt; &gt;&gt;</code> pagination.</li>
  <li><strong>Exports</strong> — CSV, JSON, and PDF. Each includes a filter context header.</li>
</ul>
<h3>Object Lookup</h3>
<p>Search for address objects, address groups, service objects, and service groups by name across the selected ADOM. Partial name matching supported. Group members are shown inline with their subnet or port details.</p>
<ul>
  <li><strong>Where Used</strong> — click the button on any result row to see which groups contain that object, and which policy rules (across all packages in the ADOM) reference it — directly by name or indirectly through a group. The <em>Via</em> column shows <em>direct</em> or the group name for indirect matches.</li>
  <li><strong>Exports</strong> — CSV, JSON, and PDF of the search results.</li>
</ul>
<h3>Interface Lookup</h3>
<p>Find which firewall interface(s) in an ADOM are assigned a given IP address.</p>
<ul>
  <li>Enter one or more IPs comma-separated (e.g. <code>10.1.2.3, 10.1.2.4</code>).</li>
  <li>The app queries every device in the ADOM and returns any interface whose IP matches exactly.</li>
  <li>Results show: Device, Interface name, VDOM, IP/mask, interface type, and link status.</li>
  <li>Devices that are unreachable are skipped with a warning banner above the results.</li>
  <li>Exports: CSV, JSON, PDF.</li>
</ul>
<h3>NAT Lookup</h3>
<p>Search VIP (Virtual IP / inbound NAT) and IP Pool (outbound PAT) objects for a given IP. Searches both the external and internal/mapped sides.</p>
<ul>
  <li>Enter a single IP address.</li>
  <li><strong>VIP match</strong> — returns if the IP equals the VIP's external IP, or falls within the mapped (internal) IP range.</li>
  <li><strong>IP Pool match</strong> — returns if the IP falls within the pool's start–end range.</li>
  <li>Results show: Type (VIP or IP Pool), name, external IP, mapped/pool IP, interface, protocol/port (for port-forwarding VIPs), and comments.</li>
  <li>Exports: CSV, JSON, PDF.</li>
</ul>
<h3>Hygiene Analysis</h3>
<ol>
  <li>Select an <strong>ADOM</strong> and <strong>Policy Package</strong> (independent from the viewer above).</li>
  <li>Choose which checks to run (all selected by default).</li>
  <li>Click <strong>Run Analysis</strong>. Findings appear in the results table.</li>
</ol>
<h3>Check Types</h3>
<ul>
  <li><strong>Unnamed rules</strong> — policies with no name set (harder to audit).</li>
  <li><strong>Unlogged rules</strong> — policies with logging disabled (traffic is invisible).</li>
  <li><strong>Shadow rules</strong> — rules that are completely covered by an earlier, broader rule and will never match.</li>
  <li><strong>Disabled rules</strong> — rules that have been turned off but left in place.</li>
  <li><strong>Expired rules</strong> — rules with a validity end date in the past.</li>
  <li><strong>Unhit rules</strong> — rules with zero bytes or sessions since creation (may be unused).</li>
  <li><strong>Missing Security Profiles</strong> — accept rules with UTM disabled, or UTM enabled but no IPS/AV/webfilter/DNS filter/application-control profile actually attached.</li>
  <li><strong>Redundant rules</strong> — a rule whose src/dst/service scope is fully covered by an earlier rule with the same action, making it a duplicate.</li>
  <li><strong>Over-permissive rules</strong> — accept rules where two or more of source, destination, and service are unrestricted (<code>all</code>/<code>ANY</code>). Severity is <em>critical</em> when all three are unrestricted, <em>high</em> when two are.</li>
</ul>
<h3>Exempting a Rule From Hygiene Checks</h3>
<p>Add the word <strong>"Exempt"</strong> anywhere in a rule's comment field (case-insensitive — e.g. <code>"Exempt -- approved by security, CHG0012345"</code>) and every hygiene check silently skips that rule on future runs, no matter which checks are selected. Use this to whitelist rules you've reviewed and intentionally kept as-is, so they stop reappearing in every report. Shadow/redundant analysis for <em>other</em> rules is unaffected — an exempted rule still counts as the "earlier, broader rule" when determining whether it shadows something else; only findings <em>about the exempted rule itself</em> are suppressed. The <strong>Hygiene Fix</strong> AI Assist mode's "Exempt (keep enabled)" option (see the Rule Validation help section) writes this same tag automatically, so choosing that fix for an over-permissive rule doubles as marking it exempt going forward.</p>
<h3>Findings Table</h3>
<ul>
  <li>Filter by check type using the dropdown. Use the search box to find specific rule names or IDs.</li>
  <li>Export findings as <strong>CSV</strong>, <strong>JSON</strong>, or <strong>PDF</strong>. Each export includes a header block showing the package, ADOM, timestamp, and active filters.</li>
</ul>
<h3>AI Explain</h3>
<p><em>If AI Assist is enabled (Admin → AI Assist):</em> expand any finding row and click <strong>Explain</strong> to get a plain-English explanation of why it matters plus a suggested FortiOS CLI remediation snippet — for that one finding only, never the whole result set. The snippet is a suggestion to review, not something the app applies for you.</p>
`
  },
  {
    id:    'device_review',
    label: 'Device Review',
    tab:   'device_review',
    html: `
<h3>Device Review</h3>
<p>Audits every FortiGate in a selected ADOM against interface protocol checks and CIS hardening benchmarks. Results are colour-coded by severity so issues stand out immediately.</p>

<h3>Running a Review</h3>
<ol>
  <li>Select an <strong>ADOM</strong> from the dropdown — the device count loads automatically.</li>
  <li>Choose which <strong>checks</strong> to run (all selected by default). Parameterised checks reveal a <strong>Check Parameters</strong> panel — enter expected values before running.</li>
  <li>Click <strong>▶ Run Review</strong>.</li>
</ol>
<p>For large ADOMs the review runs one device at a time so you can watch progress and cancel early.</p>

<h3>Progress Indicator</h3>
<ul>
  <li>A <strong>progress bar</strong> fills as each device is processed, showing <em>N / Total — current device name</em>.</li>
  <li>Click <strong>⏹ Cancel</strong> to stop after the current device. Partial results are shown immediately.</li>
</ul>

<h3>Result Values</h3>
<ul>
  <li><span style="color:#dc3545;font-weight:700">INSECURE</span> — cleartext management protocol (HTTP, Telnet) is enabled on an interface.</li>
  <li><span style="color:#dc3545;font-weight:700">FAIL</span> — CIS check failed (e.g. default admin account active, SNMP v1/v2c enabled).</li>
  <li><span style="color:#e6a817;font-weight:700">WARN</span> — interface has no secure management alternative.</li>
  <li><span style="color:#e6a817;font-weight:700">CONFIG_MISSING</span> — check ran but no expected value was supplied; device value shown for information.</li>
  <li><span style="color:#2d6a2d;font-weight:700">PASS</span> — CIS check passed.</li>
  <li><span style="color:#0d6efd;font-weight:700">INFO</span> — informational finding (e.g. HA standalone mode).</li>
</ul>

<h3>Available Checks</h3>
<p><strong>Interface Protocols</strong> — shows every interface with management access and highlights insecure cleartext protocols (HTTP, Telnet) in red.</p>
<p><strong>NTP Configuration (CIS L1)</strong> — verifies NTP sync is enabled and configured servers match expected IPs. Leave the parameter blank to see device values without comparing.</p>
<p><strong>Syslog Configuration (CIS L1)</strong> — verifies remote syslog is enabled and sending to expected server IPs.</p>

<p><em>Admin Account Hardening</em></p>
<ul>
  <li><strong>Trusted Hosts on Admin Accounts (CIS L1)</strong> — flags any admin account that allows management access from any IP (no trusted-host restriction).</li>
  <li><strong>Default 'admin' Account (CIS L1)</strong> — flags if the built-in <code>admin</code> account is still active. It should be renamed or disabled.</li>
  <li><strong>Admin Idle Timeout (CIS L1)</strong> — verifies the admin session idle timeout does not exceed your specified maximum (e.g. 10 minutes).</li>
  <li><strong>Admin Lockout Threshold (CIS L1)</strong> — verifies the failed-login lockout threshold does not exceed your specified maximum (e.g. 5 attempts).</li>
  <li><strong>Password Minimum Length (CIS L1)</strong> — verifies the password-policy minimum length meets your specified requirement (e.g. 12 characters).</li>
</ul>

<p><em>Logging</em></p>
<ul>
  <li><strong>Local Disk Logging (CIS L1)</strong> — verifies disk logging is enabled on the device.</li>
  <li><strong>Log Severity Level (CIS L1)</strong> — verifies disk log severity captures at least the expected level (e.g. <code>information</code>). Severity order: emergency → alert → critical → error → warning → notification → information → debug.</li>
  <li><strong>FortiAnalyzer Logging (CIS L1)</strong> — verifies FortiAnalyzer logging is enabled and the server IP matches expected. Leave blank to view the configured server without comparing.</li>
</ul>

<p><em>Network Services</em></p>
<ul>
  <li><strong>DNS Servers (CIS L1)</strong> — verifies all expected DNS server IPs are configured on the device.</li>
  <li><strong>SNMP Version Enforcement (CIS L1)</strong> — flags any active SNMPv1 or SNMPv2c community. Only SNMPv3 should be used.</li>
  <li><strong>SNMP Read-Only (CIS L2)</strong> — flags any SNMPv3 user with write access enabled.</li>
</ul>

<p><em>Protocol Security</em></p>
<ul>
  <li><strong>Minimum TLS Version (CIS L1)</strong> — flags if TLS 1.0 or 1.1 are permitted for HTTPS admin access. Leave the parameter blank to auto-detect without a target.</li>
  <li><strong>SSH Strong Ciphers (CIS L2)</strong> — flags if CBC-mode ciphers or MD5 MAC algorithms are in the SSH allowed list.</li>
</ul>

<p><em>Fortinet-Specific</em></p>
<ul>
  <li><strong>Firmware Version Compliance (CIS L1)</strong> — compares each device's running firmware against your specified minimum (e.g. <code>7.4.3</code>). No additional API call is needed — the version comes from the device list.</li>
  <li><strong>HA Sync Status (CIS L2)</strong> — verifies all HA cluster members are synchronised. Reports INFO for standalone devices; FAIL if any member is out of sync.</li>
</ul>

<h3>Protocol Filter Panel</h3>
<p>When the <em>Interface Protocols</em> check ran, a <strong>Filter by Protocol</strong> panel appears above the results — one checkbox per protocol found. Protocols are colour-coded:</p>
<ul>
  <li><span style="color:#dc3545;font-weight:700">Red</span> — insecure cleartext (HTTP, Telnet).</li>
  <li><span style="color:#2d6a2d;font-weight:700">Green</span> — secure (HTTPS, SSH, SNMP).</li>
  <li><span style="color:#555;font-weight:700">Grey</span> — informational (PING, FGFM, CAPWAP, etc.).</li>
</ul>
<p>The <strong>All</strong> / <strong>None</strong> buttons toggle all checkboxes at once.</p>

<h3>Results Table</h3>
<ul>
  <li>Columns: Device, Check, Result, Interface / Scope, IP Address, Protocols / Detail.</li>
  <li>Filter by free text, device, or result type using the controls above the table.</li>
  <li>Page size: 10 / 25 / 50 with <code>&lt;&lt; &lt; … &gt; &gt;&gt;</code> pagination.</li>
</ul>

<h3>CSV &amp; JSON &amp; PDF Exports</h3>
<p>CSV and JSON export all filtered rows with a metadata header. PDF exports only the selected (checked) rows and includes an evidence header: ADOM, date/time, devices reviewed, and checks run.</p>
<h3>AI Summary</h3>
<p><em>If AI Assist is enabled (Admin → AI Assist):</em> after a run completes, click <strong>Summarize with AI</strong> for a short plain-English summary of overall posture and which devices or checks need attention first. The same summary is added automatically to scheduled email/PDF reports when enabled.</p>
`
  },
  {
    id:    'rule_review',
    label: 'Rule Validation',
    tab:   'rule_review',
    html: `
<h3>Rule Validation</h3>
<p>Evaluates proposed network flows against existing FortiGate policy packages to determine whether a new rule is needed, an existing rule can be modified, or the flow is already permitted or explicitly denied.</p>
<h3>Step 1 — Define Flows</h3>
<ul>
  <li>Enter one or more flows: <strong>Source IP</strong>, <strong>Destination IP</strong>, <strong>Service / Port</strong> (e.g. <code>https</code>, <code>443</code>, <code>tcp/8443</code>), and an optional <strong>Comment</strong>.</li>
  <li>Click <strong>Add Flow</strong> to add it to the list. You can add multiple flows before proceeding.</li>
  <li>Import flows from a <strong>CSV or XLSX</strong> file using the import button (columns: src, dst, service, comment).</li>
</ul>
<h3>Step 2 — Select Packages</h3>
<ul>
  <li>Choose an <strong>ADOM</strong> then tick one or more <strong>Policy Packages</strong> to analyse.</li>
  <li>Enable <strong>Path Relevance Check</strong> to fetch live routing data from each device — this determines whether the firewall is actually in the traffic path.</li>
</ul>
<h3>Step 3 — Review Results</h3>
<p>Each flow × package combination gets a verdict:</p>
<ul>
  <li><span style="color:var(--success)"><strong>PERMITTED</strong></span> — an existing rule already allows this flow.</li>
  <li><span style="color:var(--warning)"><strong>MODIFIABLE</strong></span> — a rule covers src/dst but not the service; add the service to permit it.</li>
  <li><span style="color:var(--accent)"><strong>NEW_RULE_NEEDED</strong></span> — no matching rule exists; a suggested insert position is shown.</li>
  <li><span style="color:var(--danger)"><strong>EXPLICITLY_DENIED</strong></span> — a deny rule matches this flow.</li>
</ul>
<h3>Zone Policy Cross-check</h3>
<p>If <code>policy_db.json</code> is present, each flow is also checked against the network segmentation policy. A <strong>ZONE POLICY BLOCKED</strong> warning appears if the segmentation policy prohibits the flow, even if the firewall rule would allow it.</p>
<h3>CLI Snippets</h3>
<p>For flows that need a new or modified rule, a <strong>FortiOS CLI snippet</strong> is generated that you can paste directly into a FortiGate CLI session.</p>
<h3>AI Assist</h3>
<p><em>If AI Assist is enabled (Admin → AI Assist):</em> an alternate panel next to the bulk workflow above, with three modes selected by the buttons at the top of the panel. In every mode the verdict/plan/fix is computed deterministically first — the AI only narrates an already-computed result, and if narration fails for any reason the deterministic output is still shown.</p>
<ul>
  <li><strong>Single Change</strong> — describe one change (source, destination, service, target firewalls, plus an optional ticket ID and justification) and get back the same kind of verdict as the bulk workflow above — computed by the same engine — plus an AI-written report and peer-review package.</li>
  <li><strong>FQDN Allowlist</strong> — for vendor FQDN/wildcard allowlist requests spanning multiple entries at once (e.g. a batch of Apple push-notification hostnames). Enter the vendor, category, source IP, and target firewall(s), then either upload a vendor allowlist <code>.xlsx</code> or add rows manually (FQDN/wildcard, ports, protocol, required, comment). Produces one plan per firewall plus an AI-written report.</li>
  <li><strong>Hygiene Fix</strong> — turns a completed Rule Hygiene run's findings into deterministic remediations. Paste or upload the findings export (JSON or CSV, from either the interactive Hygiene Analysis export or a Scheduled Rule Hygiene job's email attachment), pick the ADOM + Policy Package the findings came from, and click <strong>Run</strong>. The app re-fetches the live policy package and matches each finding to its rule by policy ID — findings whose rule no longer exists (deleted or renumbered since the run) are listed separately as "stale" rather than silently dropped.
    <ul>
      <li>Findings are grouped in the results by rule, so every check that flagged the same policy ID appears together — each finding also shows "Also flagged by: ..." when other checks hit the same rule, since two findings on one rule can suggest conflicting fixes (e.g. Shadow's "narrow scope, keep enabled" vs. Unhit's "disable").</li>
      <li>Where a check has more than one valid remediation, radio buttons let you pick per-finding: <strong>Shadow</strong> offers disable / reorder above the shadowing rule / narrow the shadowing rule's scope (when it can be split safely); <strong>Over-Permissive</strong> offers disable / exempt (keep enabled, tag reviewed). Choosing <strong>Exempt</strong> writes an <code>[HygieneFix EXEMPT YYYY-MM-DD]</code> comment tag — which the Hygiene Analysis checks then recognize as an exemption (see "Exempting a Rule" in the Rule Review help section) and stop re-flagging that rule.</li>
      <li>Every comment-changing fix appends a <code>[HygieneFix YYYY-MM-DD]</code> tag so its age can be tracked; a rule already disabled and tagged more than 90 days recommends outright deletion instead.</li>
      <li>Checks with no safe automated fix (Missing Security Profiles; an Unnamed rule whose source and destination are both unrestricted) show an explanation instead of a CLI snippet — never a guessed value.</li>
      <li>Click <strong>Download HTML Report</strong> for a standalone, shareable report reflecting your current per-finding option selections — generated entirely in the browser, no server round trip.</li>
    </ul>
  </li>
</ul>
`
  },
  {
    id:    'zone_policy',
    label: 'Zone Policy',
    tab:   'zone_policy',
    html: `
<h3>Zone Policy</h3>
<p>A self-contained browser for the network segmentation policy database (<code>policy_db.json</code>). No FortiManager connection is required — all data is read from the local database.</p>
<h3>Query Flow</h3>
<ul>
  <li>Enter one or more <strong>source IPs / subnets</strong> and <strong>destination IPs / subnets</strong> (one per line, or comma-separated).</li>
  <li>Optionally enter a <strong>service</strong> (e.g. <code>ssh</code>, <code>443</code>, <code>tcp/8443</code>) to check service-specific block rules.</li>
  <li>Click <strong>Query</strong> to evaluate all src × dst combinations.</li>
</ul>
<h3>Verdicts</h3>
<ul>
  <li><span style="color:var(--success)"><strong>ALLOWED</strong></span> — an allow-all policy covers this zone pair.</li>
  <li><span style="color:var(--danger)"><strong>BLOCKED</strong></span> — a block-all or block-only (service match) policy applies.</li>
  <li><span style="color:var(--text-muted)"><strong>UNKNOWN</strong></span> — no policy rule covers this zone pair; treat as implicit deny.</span></li>
</ul>
<h3>Evaluation Order</h3>
<p>Rules are evaluated in priority order: <strong>block all</strong> &gt; <strong>block only</strong> (service match) &gt; <strong>allow all</strong>. Zone hierarchy is supported — a zone can inherit policies from its parent zones.</p>
<h3>Browse</h3>
<ul>
  <li><strong>Zones tab</strong> — accordion list of all zones with their subnets. Search by name, description, or subnet. Filter by shared/children/top-level.</li>
  <li><strong>Policies tab</strong> — full policy table. Filter by access type (allow all / block all / block only) or severity.</li>
</ul>
<h3>Validate</h3>
<p>Click <strong>Run Validation</strong> to check the database for structural errors (invalid subnets, missing zone references, empty block-only service lists, etc.).</p>
<h3>Edit Database (Admin only)</h3>
<p>Admins can add, remove, or modify zones, subnets, and policy rules directly from this panel. Changes are written immediately to <code>policy_db.json</code>.</p>
`
  },
  {
    id:    'pending_changes',
    label: 'Config-Delta',
    tab:   'pending_changes',
    html: `
<h3>Config-Delta</h3>
<p>Shows exactly which FortiOS CLI configuration lines will change on a device the next time an install is pushed to it — config that's already committed in FortiManager but not yet applied to the physical device. Everything on this tab is read-only; it triggers FortiManager's install-preview workflow but never pushes any configuration.</p>

<h3>Workflow</h3>
<ol>
  <li>Select an <strong>ADOM</strong> — the device table loads, showing every device's current sync status.</li>
  <li>Optionally filter by device name or IP, or check <strong>Pending only</strong> to show just the devices with outstanding changes.</li>
  <li>Click any device row — the diff panel populates with a per-VDOM CLI diff.</li>
  <li>Review the colour-coded diff: <strong>green</strong> lines are additions, <strong>red</strong> lines are deletions, <strong>amber</strong> lines are modifications.</li>
  <li>Click <strong>+ Add to Export Queue</strong> to stage a device, then export the queue as CSV, JSON, or PDF for a change record.</li>
</ol>

<h3>Status Badges</h3>
<ul>
  <li><strong>Out of Sync</strong> — the device's running config has drifted from FortiManager; a re-install is required.</li>
  <li><strong>Pending</strong> — FortiManager's database has changes not yet pushed to the device.</li>
  <li><strong>Pkg Pending</strong> — the policy package was modified in FortiManager but not yet installed.</li>
  <li><strong>In Sync</strong> — the device is fully in sync with FortiManager.</li>
</ul>

<h3>AI Summary</h3>
<p><em>If AI Assist is enabled (Admin → AI Assist):</em> click <strong>Summarize with AI</strong> in the diff panel for a short plain-English description of what's actually changing — new/removed policies, address or service object changes, routing changes. The raw CLI diff is always shown unmodified alongside the summary. Scheduled export emails include the same summary automatically when enabled (see the <strong>Scheduled Jobs</strong> help section).</p>
`
  },
  {
    id:    'map_view',
    label: 'Map (Beta)',
    tab:   'map_view',
    html: `
<h3>Device Location Map (Beta)</h3>
<p>An interactive map showing the geographic location of all managed FortiGate devices. Locations come from the latitude/longitude coordinates set on each device in FortiManager — devices with no coordinates set (0.0 / 0.0) are excluded.</p>

<h3>Map Behaviour</h3>
<ul>
  <li><strong>Zoom out</strong> — nearby devices cluster into a single circle showing the count. The circle colour reflects the dominant region at that location.</li>
  <li><strong>Zoom in</strong> — clusters split apart until individual device pins appear at city level.</li>
  <li><strong>Click a cluster</strong> — zooms in to expand it.</li>
  <li><strong>Click a pin</strong> — opens a popup showing the device name, region, ADOM, platform, version, description, online status, and exact coordinates.</li>
</ul>

<h3>Region Colours</h3>
<p>Device pins are colour-coded by US geographic region. Each region groups a set of states and is assigned a distinct colour. The legend above the map shows the current colour for each region. Any device in a state not assigned to a named region appears in the <strong>Other</strong> colour.</p>
<p>Admins can change the pin colour for any region (including <strong>Other</strong>) in <strong>&#9881; Admin → Map Region Colors</strong>. Color changes take effect on the next map page load.</p>

<h3>Legend &amp; ADOM Filter</h3>
<p>The legend shows each region with its colour. Use the <strong>ADOM filter checkboxes</strong> to show or hide devices by ADOM — useful for focusing on a specific environment (e.g. OT-SERVICES only). The <strong>All</strong> and <strong>None</strong> buttons quickly toggle all checkboxes at once.</p>

<h3>Status Bar</h3>
<p>A status bar below the page header shows the current state of the location cache:</p>
<ul>
  <li>Spinning — data is being fetched from FortiManager (happens at startup or after a manual refresh).</li>
  <li>The bar shows per-ADOM progress: <em>N / Total ADOMs — current ADOM name</em>.</li>
  <li>Once complete the bar disappears and the <em>Updated N minutes ago</em> timestamp updates.</li>
</ul>

<h3>Data Freshness</h3>
<p>Location data is cached in memory and refreshed once a day at startup (configurable via <code>MAP_CACHE_INTERVAL_HOURS</code> in <code>.env</code>). Device coordinates rarely change, so daily refresh is sufficient. The timestamp below the page title shows when the cache was last built.</p>

<h3>Refresh Button (Admin only)</h3>
<p>Admin users see a <strong>↺ Refresh Data</strong> button. Clicking it queues an immediate background refresh and shows the progress bar. The map updates automatically when the new data is ready — no page reload needed.</p>

<h3>Missing Devices</h3>
<p>Devices are only shown if their latitude and longitude are set to a non-zero value in FortiManager (<strong>Device Manager → device properties → Location</strong>). Devices showing <code>0.0 / 0.0</code> are silently excluded. If a device you expect to see is missing, check its location in FortiManager.</p>

<h3>Device Details</h3>
<p>When you click a device pin, the popup includes a <strong>View Details →</strong> link (visible only if you have access to the Firewalls tab). Clicking it takes you directly to the Firewalls tab with that device's search pre-filled and its detail panel opened automatically. Users without Firewalls tab access will not see the link.</p>

<h3>Health Status Ledger</h3>
<p>A compact overlay in the bottom-right corner of the screen shows the total device count by health status:</p>
<ul>
  <li><span class="status-dot green" style="display:inline-block;vertical-align:middle"></span> <strong>Green</strong> — healthy devices</li>
  <li><span class="status-dot yellow" style="display:inline-block;vertical-align:middle"></span> <strong>Yellow</strong> — warning (CPU or memory elevated)</li>
  <li><span class="status-dot red" style="display:inline-block;vertical-align:middle"></span> <strong>Red</strong> — critical or unreachable</li>
  <li><span class="status-dot offline" style="display:inline-block;vertical-align:middle"></span> <strong>Grey</strong> — offline or status unknown</li>
</ul>
<p>The counts reflect the full fleet regardless of which ADOMs are currently shown via the filter checkboxes. The ledger appears once map data has loaded and remains visible as you scroll or zoom.</p>
`
  },
  {
    id:    'scheduled',
    label: 'Scheduled Jobs',
    html: `
<h3>Scheduled Jobs</h3>
<p>The <strong>Scheduled</strong> sub-tab in the Admin panel lets admins create recurring automated reports. Two job types are available: <strong>Config-Delta</strong> (pending configuration diffs) and <strong>Device Review</strong> (CIS hardening audit). Both use the same SMTP settings configured at the top of the panel.</p>

<h3>SMTP Settings</h3>
<p>Before creating any scheduled job, configure the outbound mail server:</p>
<ul>
  <li><strong>Host</strong> — SMTP server hostname or IP.</li>
  <li><strong>Port</strong> — typically 587 (STARTTLS) or 465 (SSL).</li>
  <li><strong>TLS</strong> — enable for STARTTLS; use port 465 for implicit SSL.</li>
  <li><strong>Username / Password</strong> — leave blank for unauthenticated relays.</li>
  <li><strong>From address</strong> — the sender address that appears in delivered emails.</li>
</ul>
<p>Click <strong>Test Email</strong> to send a test message and verify the settings before saving.</p>

<h3>Config-Delta Scheduled Jobs</h3>
<p>Generates and emails pending configuration diffs (changes committed in FortiManager but not yet pushed to devices) for an entire ADOM on a recurring schedule.</p>
<ul>
  <li><strong>ADOM</strong> — the FortiManager ADOM to sweep.</li>
  <li><strong>Days</strong> — one or more days of the week (e.g. Mon + Thu).</li>
  <li><strong>Time</strong> — HH:MM (24-hour) when the job fires.</li>
  <li><strong>Format</strong> — PDF (HTML), CSV, or JSON attachment.</li>
  <li><strong>Email</strong> — comma-separated recipient list.</li>
  <li><strong>Enabled</strong> — uncheck to pause the job without deleting it.</li>
</ul>
<p>Click <strong>Run Now</strong> on any job row to fire it immediately outside the schedule.</p>

<h3>Device Review Scheduled Jobs</h3>
<p>Runs CIS hardening checks against every device in an ADOM on a recurring schedule and emails the results.</p>
<ul>
  <li><strong>Name</strong> — a label for this job (e.g. "Weekly CIS Audit — Enterprise").</li>
  <li><strong>ADOM</strong> — the FortiManager ADOM to audit.</li>
  <li><strong>Days / Time</strong> — same as Config-Delta above.</li>
  <li><strong>Checks</strong> — choose any subset of the 18 available checks. Leave all ticked to run the full audit.</li>
  <li><strong>Check Parameters</strong> — appears below the checklist for any parameterised check you have ticked. Supply expected values (e.g. NTP server IPs, minimum firmware version) before saving. Checks with no parameter supplied run as <code>CONFIG_MISSING</code> — the device value is shown without comparison.</li>
  <li><strong>Format</strong> — PDF (HTML), CSV, or JSON attachment.</li>
  <li><strong>Email</strong> — comma-separated recipient list.</li>
  <li><strong>Enabled</strong> — uncheck to pause without deleting.</li>
</ul>

<h3>Email Report Format</h3>
<p>Each Device Review email contains two parts:</p>
<ul>
  <li><strong>Email body</strong> — a summary table showing pass / fail / warn counts per check across all devices.</li>
  <li><strong>Attachment</strong> — the full findings detail in your chosen format:
    <ul>
      <li><strong>PDF (HTML)</strong> — styled HTML table with Device, Check, Result, Interface, VDOM, IP, and Detail columns. Result values are colour-coded (red = FAIL/INSECURE, amber = WARN/CONFIG_MISSING, green = PASS, blue = INFO).</li>
      <li><strong>CSV</strong> — same columns as the HTML report, with a metadata header block at the top (ADOM, timestamp).</li>
      <li><strong>JSON</strong> — complete row objects including the full <code>protocols</code> list for Interface Protocols findings.</li>
    </ul>
  </li>
</ul>

<h3>Run History</h3>
<p>Each job row shows a <strong>Last Run</strong> status (ok / error) and timestamp. Click the status chip to expand the last 5 run records inline. Run history is retained for 30 days by default (configurable via <code>run_history_days</code> in SMTP settings).</p>

<h3>Parameterised Checks — Quick Reference</h3>
<table style="border-collapse:collapse;font-size:12px;width:100%">
  <thead><tr style="background:var(--bg-secondary)">
    <th style="padding:3px 6px;text-align:left">Check</th>
    <th style="padding:3px 6px;text-align:left">Parameter</th>
    <th style="padding:3px 6px;text-align:left">Example</th>
  </tr></thead>
  <tbody>
    <tr><td style="padding:3px 6px">NTP Configuration</td><td style="padding:3px 6px">Expected server IPs</td><td style="padding:3px 6px"><code>10.1.1.1, 10.1.1.2</code></td></tr>
    <tr><td style="padding:3px 6px">Syslog Configuration</td><td style="padding:3px 6px">Expected server IPs</td><td style="padding:3px 6px"><code>10.2.2.1</code></td></tr>
    <tr><td style="padding:3px 6px">Admin Idle Timeout</td><td style="padding:3px 6px">Max minutes</td><td style="padding:3px 6px"><code>10</code></td></tr>
    <tr><td style="padding:3px 6px">Admin Lockout Threshold</td><td style="padding:3px 6px">Max attempts</td><td style="padding:3px 6px"><code>5</code></td></tr>
    <tr><td style="padding:3px 6px">Password Minimum Length</td><td style="padding:3px 6px">Min characters</td><td style="padding:3px 6px"><code>12</code></td></tr>
    <tr><td style="padding:3px 6px">Log Severity Level</td><td style="padding:3px 6px">Max severity</td><td style="padding:3px 6px"><code>information</code></td></tr>
    <tr><td style="padding:3px 6px">FortiAnalyzer Logging</td><td style="padding:3px 6px">Expected FAZ IP</td><td style="padding:3px 6px"><code>10.3.3.1</code></td></tr>
    <tr><td style="padding:3px 6px">DNS Servers</td><td style="padding:3px 6px">Expected server IPs</td><td style="padding:3px 6px"><code>8.8.8.8, 8.8.4.4</code></td></tr>
    <tr><td style="padding:3px 6px">Minimum TLS Version</td><td style="padding:3px 6px">Min TLS version</td><td style="padding:3px 6px"><code>tlsv1-2</code></td></tr>
    <tr><td style="padding:3px 6px">Firmware Version Compliance</td><td style="padding:3px 6px">Minimum version</td><td style="padding:3px 6px"><code>7.4.3</code></td></tr>
  </tbody>
</table>
`
  },
  {
    id:    'admin',
    label: 'Admin',
    html: `
<h3>Administration Panel</h3>
<p>Accessible to <strong>admin</strong> accounts only via the <strong>&#9881; Admin</strong> link in the navigation bar. Sub-tabs: <strong>Groups &amp; Permissions</strong>, <strong>Map Region Colors</strong>, <strong>External API</strong>, <strong>AI Assist</strong>, <strong>Scheduled</strong>, <strong>Backup</strong>, <strong>Zone Policy</strong>, and <strong>Application Logs</strong>.</p>

<h3>Host Resource Graphs</h3>
<p>Above the sub-tab bar, three graphs (CPU, Memory, Disk) show resource usage of the host running the app, sampled every 60 seconds. Use the range pills (1h / 4h / 12h / 1d / 7d / 14d) to zoom out. If AI Assist is enabled, a <strong>Generate AI Trend Summary</strong> button appears above the graphs — it computes 7-day trend statistics (percent change, slope, a days-to-threshold projection) deterministically, then has the AI phrase a short readable summary of anything that needs attention.</p>

<h3>Groups &amp; Permissions</h3>
<p>Groups control two things for non-admin users: which <strong>navigation tabs</strong> they can see and which <strong>ADOMs</strong> they can access.</p>
<ul>
  <li>Admin role users always have full access to every tab and every ADOM, regardless of group membership.</li>
  <li>Non-admin users get the <em>union</em> of allowed tabs across all groups they belong to.</li>
  <li>If a user is in no group they see no tabs and no ADOMs.</li>
</ul>

<h3>ADOM Access Control</h3>
<p>Each group has an optional ADOM restriction. When editing a group, check <strong>Restrict ADOM access for this group</strong> to enable it.</p>
<ul>
  <li><strong>Unrestricted (default)</strong> — members see all ADOMs in every tab that the group allows.</li>
  <li><strong>Restricted</strong> — members can only see the specific ADOMs ticked in the <em>Allowed ADOMs</em> list.</li>
</ul>
<p>The ADOM list is populated automatically from FortiManager at startup and refreshed every 30 minutes. If FortiManager is unreachable the list shows whatever was last loaded.</p>
<p><strong>Important:</strong> If a user belongs to multiple groups and even one of them is unrestricted, that user gets full ADOM access. Restrictions only take effect when <em>all</em> of a user's groups have ADOM restrict enabled.</p>
<p>New ADOMs discovered from FortiManager are <em>not</em> automatically added to any group's allowed list — this is intentional. Restricted groups must be explicitly updated to grant access to a newly discovered ADOM.</p>

<h3>Map Region Colors</h3>
<p>The <strong>Map Region Colors</strong> sub-tab lets admins fully configure the US geographic regions used to colour device pins on the map.</p>
<ul>
  <li><strong>Add a region</strong> — click <strong>+ Add Region</strong>, type a name, pick states and a colour.</li>
  <li><strong>Rename a region</strong> — edit the name field directly in the table row.</li>
  <li><strong>Delete a region</strong> — click the <strong>&times;</strong> button on the right; its states move back to the <em>Other</em> pool automatically.</li>
  <li><strong>Reassign states</strong> — use the multi-select in each row. Hold <strong>Ctrl</strong> (Windows/Linux) or <strong>Cmd</strong> (Mac) to select multiple states. A state can only belong to one region — selecting it here disables it in all other region lists.</li>
</ul>
<p>The <strong>Other</strong> row at the bottom controls the colour for any device in a state not assigned to a named region. Click <strong>Save</strong> to persist all changes — the map uses the new settings on the next page load. If all regions are deleted, every device falls back to the <em>Other</em> colour.</p>

<h3>External API</h3>
<p>Lets external programs query Zone Policy data over a bearer-token API, without a browser session. Disabled by default — check <strong>External API enabled</strong> and save to turn it on. Create tokens with <strong>+ New Token</strong>; the plaintext value is shown once and never again, so copy it immediately. Tokens can be revoked at any time. When disabled, every <code>/external/api/</code> request returns <code>503</code> regardless of token validity.</p>

<h3>AI Assist</h3>
<p>One <strong>ai_assist_enabled</strong> toggle turns on every AI feature in the app at once — Rule Validation's AI Assist, Device Review's AI Summary, Config-Delta's AI Summary, Rule Review's AI Explain, and the Admin AI Trend Summary. Off by default. This sub-tab also shows an AI usage/cost chart — every LLM call the app makes (which provider, how many tokens, estimated cost) is tracked here regardless of which feature triggered it.</p>

<h3>Backup</h3>
<p>Creates AES-256 encrypted ZIP backups of all runtime configuration. <strong>One-time backups</strong> download directly to your browser. <strong>Scheduled backups</strong> (daily/weekly/custom) run server-side and can optionally push the archive to a remote FTP or SFTP server. The backup password is shown once on first save, the same as API tokens — store it offline, it cannot be retrieved again. The last 20 local archives are kept automatically; older ones are pruned.</p>

<h3>Zone Policy (Edit Database)</h3>
<p>Admin-only zone policy database editing lives here rather than on the Zone Policy tab itself, so every write to <code>policy_db.json</code> is admin-gated in one place. Add, remove, or modify zones, subnets, and policy rules — changes are written back atomically and take effect immediately for every user on the Zone Policy tab.</p>

<h3>Application Logs</h3>
<p>An in-memory ring buffer showing up to 2,000 recent log entries (cleared on restart). Use the level and component filters to narrow results. Levels: TRACE → DEBUG → INFO → WARN → ERROR.</p>
`
  },
  {
    id:    'faq',
    label: 'FAQ',
    html: `
<h3>Frequently Asked Questions</h3>

<div class="help-faq">
  <div class="faq-q">Why does a dashboard card show 0% CPU and Memory?</div>
  <div class="faq-a">FortiManager may return CPU/memory data in a format that varies by version. If this happens, your administrator can browse to <code>/api/infrastructure/raw</code> (admin accounts only) to see the exact raw API response and diagnose the field names.</div>

  <div class="faq-q">Why is the device detail showing "n/a" for some fields?</div>
  <div class="faq-a">Some fields (uptime, interfaces, routes) come from live proxy calls to the FortiGate via FortiManager. If the device is offline or FortiManager cannot reach it, those calls return empty. Fields sourced from the FortiManager database (hostname, serial, version, platform) should always be populated if the device is registered.</div>

  <div class="faq-q">Why does the Firewalls page not show any devices?</div>
  <div class="faq-a">Select an ADOM from the dropdown first. If the dropdown itself is empty, FortiManager returned no ADOMs — check that the API account has the correct read permissions in FortiManager.</div>

  <div class="faq-q">Can I use this dashboard to make changes to a device?</div>
  <div class="faq-a">No. 4THealth+ is strictly read-only. All API calls use <code>action: get</code> — no configuration endpoints are ever called.</div>

  <div class="faq-q">How do I log out?</div>
  <div class="faq-a">Click the <strong>Logout</strong> button in the top-right corner. Your session expires automatically after 1 hour of inactivity regardless.</div>

  <div class="faq-q">Why does Rule Validation show a ZONE POLICY BLOCKED warning even though the firewall rule permits the flow?</div>
  <div class="faq-a">The zone policy is a segmentation policy layer that sits above individual firewall rules. A BLOCKED verdict from the zone policy means the network architecture does not permit this traffic regardless of what any single firewall rule says. Resolve the zone policy issue first before requesting a firewall rule change.</div>

  <div class="faq-q">The Zone Policy tab says "policy_db.json not found". What do I do?</div>
  <div class="faq-a">Copy a valid <code>policy_db.json</code> to the project root directory and restart the application. Ask your administrator for the current database file.</div>

  <div class="faq-q">How do I add or remove user accounts?</div>
  <div class="faq-a">Run <code>uv run python manage_users.py add &lt;username&gt; --role admin|viewer</code> on the server. Tab and ADOM access is controlled per-group by an administrator via the Admin panel.</div>

  <div class="faq-q">Why can't a user see certain ADOMs in the Firewalls or Rule Review dropdown?</div>
  <div class="faq-a">The user's group has ADOM restriction enabled and that ADOM is not in the group's allowed list. An admin can edit the group in the Admin panel to add the ADOM. Admins always see all ADOMs.</div>

  <div class="faq-q">A new ADOM appeared in FortiManager but restricted users can't see it. Why?</div>
  <div class="faq-a">By design — new ADOMs are never automatically granted to restricted groups. An admin must edit each restricted group and tick the new ADOM in the Allowed ADOMs list.</div>

  <div class="faq-q">I see "Authentication failed" on a dashboard card. What does that mean?</div>
  <div class="faq-a">The application could not log into that appliance using the configured API credentials. Verify that the <code>FMG_API_TOKEN</code> (or <code>FMG_USERNAME</code> / <code>FMG_PASSWORD</code>) values in <code>.env</code> are correct.</div>

  <div class="faq-q">The route table shows thousands of rows. Is there a faster way to find a route?</div>
  <div class="faq-a">Yes — use the filter box above the route table in the device detail panel. Type any part of the destination network, gateway IP, or interface name to narrow down the list instantly.</div>

  <div class="faq-q">Device Review shows no interfaces even though I know protocols are configured.</div>
  <div class="faq-a">The review fetches interfaces via FortiManager's proxy API. If the device is offline or FortiManager cannot reach it, the interface list will be empty for that device. Devices that return no data are silently skipped — they are still counted in "devices reviewed" but contribute no rows to the results.</div>

  <div class="faq-q">Why does the Device Review take a long time for a large ADOM?</div>
  <div class="faq-a">Each device requires a separate API call through FortiManager. The review processes one device at a time so you can watch progress and cancel early. For an ADOM with 700+ devices expect several minutes. Use the <strong>⏹ Cancel</strong> button to stop and work with partial results.</div>

  <div class="faq-q">The Device Versions "All ADOMs" chart is spinning and not loading.</div>
  <div class="faq-a">The chart is built from a background cache that populates at startup. On first launch it may take a few minutes to sweep all ADOMs. The page polls automatically every 3 seconds until the cache is ready — just leave the tab open and it will fill in. Click <strong>↻ Refresh</strong> to trigger a fresh sweep at any time.</div>

  <div class="faq-q">A device I expect to see on the Map is missing.</div>
  <div class="faq-a">The map only shows devices with a non-zero latitude and longitude set in FortiManager. In FortiManager, open <strong>Device Manager → select the device → Edit → Location tab</strong> and set the coordinates. After saving, an admin can click <strong>↺ Refresh Data</strong> on the map page to pull the updated location immediately.</div>

  <div class="faq-q">The Map status bar says "Location data is warming up" after startup.</div>
  <div class="faq-a">The location cache is built in the background at startup. It sweeps all ADOMs to collect device coordinates — this typically takes under a minute. The map polls automatically and will populate as soon as the cache is ready.</div>
</div>
`
  }
];

/* ── Filter sections by allowed tabs ────────────────────────────────────── */
const allowed = new Set(window._helpAllowedTabs || []);

function visibleSections() {
  return SECTIONS.filter(s => !s.tab || allowed.has(s.tab));
}

/* ── Build and inject the panel ──────────────────────────────────────────── */
function buildPanel() {
  const sections = visibleSections();
  if (!sections.length) return;

  const tabBtns = sections.map((s, i) =>
    `<button class="help-tab${i === 0 ? ' active' : ''}" data-tab="${s.id}">${s.label}</button>`
  ).join('');

  const tabPanes = sections.map((s, i) =>
    `<div class="help-pane${i === 0 ? ' active' : ''}" id="help-pane-${s.id}">${s.html}</div>`
  ).join('');

  const panel = document.createElement('div');
  panel.id        = 'helpPanel';
  panel.className = 'help-panel hidden';
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-modal', 'true');
  panel.setAttribute('aria-label', 'Help');
  panel.innerHTML = `
<div class="help-panel-inner">
  <div class="help-header">
    <span class="help-title">&#10067; Help &amp; Guide</span>
    <button class="help-close" id="helpClose" aria-label="Close help">&times;</button>
  </div>
  <div class="help-tabs">${tabBtns}</div>
  <div class="help-body">${tabPanes}</div>
</div>`;

  document.body.appendChild(panel);

  const backdrop = document.createElement('div');
  backdrop.id        = 'helpBackdrop';
  backdrop.className = 'help-backdrop hidden';
  document.body.appendChild(backdrop);
}

/* ── Wire interactions ───────────────────────────────────────────────────── */
function wirePanel() {
  const panel    = document.getElementById('helpPanel');
  const backdrop = document.getElementById('helpBackdrop');
  const btn      = document.getElementById('helpBtn');

  if (!panel) return;

  function open() {
    panel.classList.remove('hidden');
    backdrop.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
  }
  function close() {
    panel.classList.add('hidden');
    backdrop.classList.add('hidden');
    document.body.style.overflow = '';
  }

  btn.addEventListener('click', open);
  document.getElementById('helpClose').addEventListener('click', close);
  backdrop.addEventListener('click', close);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') close(); });

  panel.querySelectorAll('.help-tab').forEach(tab => {
    tab.addEventListener('click', function () {
      panel.querySelectorAll('.help-tab').forEach(t => t.classList.remove('active'));
      panel.querySelectorAll('.help-pane').forEach(p => p.classList.remove('active'));
      this.classList.add('active');
      document.getElementById(`help-pane-${this.dataset.tab}`).classList.add('active');
    });
  });
}

/* ── Init ────────────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  if (!document.getElementById('helpBtn')) return;
  buildPanel();
  wirePanel();
});

})();
