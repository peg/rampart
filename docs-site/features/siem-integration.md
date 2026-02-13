# SIEM Integration

Send Rampart audit events to your existing security stack. Three output formats, works with any SIEM.

## Output Formats

=== "Syslog (RFC 5424)"

    ```bash
    rampart serve --syslog localhost:514
    ```

    Works with: Wazuh, QRadar, ArcSight, LogRhythm, Sentinel

=== "CEF (Common Event Format)"

    ```bash
    rampart serve --syslog localhost:514 --cef
    ```

    Works with: Splunk, QRadar, ArcSight, Exabeam

    ```
    CEF:0|Rampart|PolicyEngine|0.1.10|deny|Destructive command blocked|8|src=claude-code cmd=rm -rf / policy=exec-safety
    ```

=== "CEF to File"

    ```bash
    rampart serve --cef
    ```

    When you don't have a syslog collector. Works on all platforms.

All outputs run alongside the default JSONL audit trail — you don't lose anything by enabling SIEM output.

## Wazuh Integration

Complete setup guide for Wazuh, the most popular open-source SIEM.

### 1. Configure Wazuh Agent

Add to `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/home/YOUR_USER/.rampart/audit/*.jsonl</location>
  <label key="source">rampart</label>
</localfile>
```

### 2. Add Custom Decoder

Create `/var/ossec/etc/decoders/rampart_decoder.xml`:

```xml
<decoder name="rampart">
  <prematch>^{"id":</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

### 3. Add Custom Rules

Create `/var/ossec/etc/rules/rampart_rules.xml`:

```xml
<group name="rampart,ai_agent_security">

  <!-- Base rule -->
  <rule id="100300" level="0">
    <decoded_as>json</decoded_as>
    <field name="source">rampart</field>
    <description>Rampart audit event</description>
  </rule>

  <!-- Allow (informational) -->
  <rule id="100301" level="3">
    <if_sid>100300</if_sid>
    <field name="action">allow</field>
    <description>Rampart: AI agent tool call allowed</description>
  </rule>

  <!-- Log (notable) -->
  <rule id="100302" level="5">
    <if_sid>100300</if_sid>
    <field name="action">log</field>
    <description>Rampart: AI agent tool call logged</description>
  </rule>

  <!-- Deny (alert) -->
  <rule id="100303" level="10">
    <if_sid>100300</if_sid>
    <field name="action">deny</field>
    <description>Rampart: AI agent tool call BLOCKED</description>
  </rule>

  <!-- High-frequency denials (possible attack) -->
  <rule id="100305" level="12" frequency="5" timeframe="60">
    <if_matched_sid>100303</if_matched_sid>
    <description>Rampart: Multiple blocks in 60s — possible prompt injection</description>
  </rule>

  <!-- Credential access attempt -->
  <rule id="100306" level="12">
    <if_sid>100303</if_sid>
    <field name="policy_name">protect-credentials|block-credential</field>
    <description>Rampart: AI agent attempted credential access</description>
  </rule>

  <!-- Exfiltration attempt -->
  <rule id="100307" level="13">
    <if_sid>100303</if_sid>
    <field name="policy_name">block-exfil|encoded-data-exfil</field>
    <description>Rampart: AI agent attempted data exfiltration</description>
  </rule>

</group>
```

### 4. Restart Services

```bash
sudo systemctl restart wazuh-agent
sudo systemctl restart wazuh-manager
```

### Alert Levels

| Rampart Action | Wazuh Level | Description |
|---------------|-------------|-------------|
| allow | 3 | Informational |
| log | 5 | Notable |
| require_approval | 8 | Needs human review |
| deny | 10 | Blocked by policy |
| deny (credentials) | 12 | Credential access attempt |
| deny (exfiltration) | 13 | Data exfiltration attempt |
| 5+ denials in 60s | 12 | Possible prompt injection |

### FIM Recommendations

AI agent hosts generate many files. Bump the FIM limit and exclude noise:

```xml
<syscheck>
  <file_limit>
    <enabled>yes</enabled>
    <entries>500000</entries>
  </file_limit>

  <!-- Realtime on security-critical paths -->
  <directories check_all="yes" realtime="yes">/home/*/.ssh</directories>
  <directories check_all="yes" realtime="yes">/home/*/.rampart/policies</directories>

  <!-- Skip build noise -->
  <ignore type="sregex">node_modules|\.cache|\.npm|__pycache__|\.git/objects</ignore>
</syscheck>
```

## Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| `--syslog` | ✅ | ✅ | ❌ |
| `--cef` (file) | ✅ | ✅ | ✅ |
| JSONL audit | ✅ | ✅ | ✅ |
