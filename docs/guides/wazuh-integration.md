# Integrating Rampart with Wazuh

Monitor AI agent activity and trigger alerts when Rampart blocks dangerous operations.

## Overview

Rampart logs every tool call decision to JSON files in `~/.rampart/audit/`. Wazuh can monitor these files, decode the events, and generate alerts based on deny/log actions — giving your SOC visibility into AI agent behavior alongside your existing security monitoring.

## Architecture

```
AI Agent → Rampart (policy evaluation) → Audit Log (JSONL)
                                              ↓
                                     Wazuh Agent (localfile)
                                              ↓
                                     Wazuh Manager (rules)
                                              ↓
                                     Wazuh Dashboard (alerts)
```

## Setup

### 1. Configure Wazuh Agent to Monitor Audit Files

Add to your Wazuh agent's `ossec.conf` (typically `/var/ossec/etc/ossec.conf`):

```xml
<localfile>
  <log_format>json</log_format>
  <location>/home/YOUR_USER/.rampart/audit/*.jsonl</location>
  <label key="source">rampart</label>
</localfile>
```

Restart the Wazuh agent:

```bash
sudo systemctl restart wazuh-agent
```

### 2. Add Custom Decoder

Create `/var/ossec/etc/decoders/rampart_decoder.xml` on the Wazuh manager:

```xml
<decoder name="rampart">
  <prematch>^{"id":</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

### 3. Add Custom Rules

Create `/var/ossec/etc/rules/rampart_rules.xml` on the Wazuh manager:

```xml
<group name="rampart,ai_agent_security">

  <!-- Base rule: any Rampart event -->
  <rule id="100300" level="0">
    <decoded_as>json</decoded_as>
    <field name="source">rampart</field>
    <description>Rampart audit event</description>
  </rule>

  <!-- Allow actions (informational) -->
  <rule id="100301" level="3">
    <if_sid>100300</if_sid>
    <field name="action">allow</field>
    <description>Rampart: AI agent tool call allowed - $(tool) - $(command)</description>
    <group>rampart_allow</group>
  </rule>

  <!-- Log actions (notable) -->
  <rule id="100302" level="5">
    <if_sid>100300</if_sid>
    <field name="action">log</field>
    <description>Rampart: AI agent tool call logged - $(tool) - $(command)</description>
    <group>rampart_log</group>
  </rule>

  <!-- Deny actions (security event) -->
  <rule id="100303" level="10">
    <if_sid>100300</if_sid>
    <field name="action">deny</field>
    <description>Rampart: AI agent tool call BLOCKED - $(tool) - $(command)</description>
    <group>rampart_deny</group>
  </rule>

  <!-- Approval required -->
  <rule id="100304" level="8">
    <if_sid>100300</if_sid>
    <field name="action">require_approval</field>
    <description>Rampart: AI agent tool call requires approval - $(tool) - $(command)</description>
    <group>rampart_approval</group>
  </rule>

  <!-- High-frequency denials (possible attack or prompt injection) -->
  <rule id="100305" level="12" frequency="5" timeframe="60">
    <if_matched_sid>100303</if_matched_sid>
    <description>Rampart: Multiple AI agent tool calls blocked in 60 seconds — possible prompt injection or malicious behavior</description>
    <group>rampart_attack</group>
  </rule>

  <!-- Credential access attempt -->
  <rule id="100306" level="12">
    <if_sid>100303</if_sid>
    <field name="policy_name">protect-credentials|block-credential-exfil|encoding-sensitive-files</field>
    <description>Rampart: AI agent attempted credential access - $(command)</description>
    <group>rampart_credential_access</group>
  </rule>

  <!-- Exfiltration attempt -->
  <rule id="100307" level="13">
    <if_sid>100303</if_sid>
    <field name="policy_name">block-exfil-domains|encoded-data-exfil|block-encoding-exfil</field>
    <description>Rampart: AI agent attempted data exfiltration - $(command)</description>
    <group>rampart_exfiltration</group>
  </rule>

</group>
```

Restart the Wazuh manager:

```bash
sudo systemctl restart wazuh-manager
```

### 4. Verify

Trigger a test deny event:

```bash
# With rampart serve running
curl -s http://localhost:19090/evaluate \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tool":"exec","params":{"command":"cat ~/.ssh/id_rsa"}}'
```

Check the Wazuh dashboard for a level 10+ alert from rule 100303 or 100306.

## Syslog Output (v0.1.7+)

For direct syslog integration without file monitoring:

```bash
# Send audit events to syslog (JSON format)
rampart serve --syslog localhost:514

# Send in CEF format (Common Event Format) for Splunk/QRadar/ArcSight
rampart serve --syslog localhost:514 --cef
```

CEF output format:

```
CEF:0|Rampart|PolicyEngine|0.1.7|deny|Destructive command blocked|8|src=claude-code cmd=rm -rf / policy=exec-safety
```

## Alert Levels

| Rampart Action | Wazuh Level | Description |
|---------------|-------------|-------------|
| allow | 3 | Informational — normal operation |
| log | 5 | Notable — flagged for review |
| require_approval | 8 | Security event — needs human approval |
| deny | 10 | Alert — blocked by policy |
| deny (credentials) | 12 | High alert — credential access attempt |
| deny (exfiltration) | 13 | Critical — data exfiltration attempt |
| 5+ denials in 60s | 12 | Correlation — possible prompt injection |

## Dashboard Visualization

In Wazuh Dashboard, create a custom visualization:

- **Index pattern:** `wazuh-alerts-*`
- **Filter:** `rule.groups: rampart`
- **Useful fields:** `data.tool`, `data.action`, `data.command`, `data.policy_name`, `data.agent`

## Compatibility

- Wazuh 4.x and later
- Works with Wazuh single-node and cluster deployments
- File monitoring works with any Wazuh agent (Linux, macOS)
- Syslog output works with any syslog-compatible SIEM
