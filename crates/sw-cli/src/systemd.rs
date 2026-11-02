pub const SYSTEMD_UNIT_TEMPLATE: &str = r#"[Unit]
Description=SilverWarden Bitwarden-compatible vault agent
Documentation=https://github.com/d-ariza/SilverWarden-RS
After=graphical-session.target
PartOf=graphical-session.target

[Service]
Type=simple
ExecStart={exec_path} agent start
Restart=on-failure
RestartSec=5s
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
"#;

pub const POLKIT_POLICY_TEMPLATE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>SilverWarden</vendor>
  <vendor_url>https://github.com/d-ariza/SilverWarden-RS</vendor_url>
  <action id="org.silverwarden.unlock">
    <description>Unlock the SilverWarden vault</description>
    <message>Authentication is required to unlock the SilverWarden vault</message>
    <defaults>
      <allow_any>auth_self</allow_any>
      <allow_inactive>auth_self</allow_inactive>
      <allow_active>auth_self</allow_active>
    </defaults>
  </action>
</policyconfig>
"#;

pub fn render_systemd_unit(exec_path: &str) -> String {
    SYSTEMD_UNIT_TEMPLATE.replace("{exec_path}", exec_path)
}

pub fn render_polkit_policy() -> String {
    POLKIT_POLICY_TEMPLATE.to_string()
}
