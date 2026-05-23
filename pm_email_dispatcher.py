import smtplib
import re
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from jinja2 import Template

class PMEmailDispatcher:
    def __init__(self, smtp_host, smtp_port=25, sender_email=None, sender_name="GTBank IT Security", 
                 email_domain=None, use_tls=False, smtp_user=None, smtp_pass=None, 
                 cc_security_team=None, dry_run=False):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_name = sender_name
        self.email_domain = email_domain
        self.use_tls = use_tls
        self.smtp_user = smtp_user
        self.smtp_pass = smtp_pass
        self.cc_security_team = cc_security_team
        self.dry_run = dry_run

        # HTML Templates
        self.subnet_template = Template("""
        <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <p>Dear {{ first_name }},</p>
            <p>Our security monitoring systems have detected unusual login activity on your ProcessMaker account.</p>
            <p>It appears that your account has been accessed from multiple distinct network locations recently. Below is a summary of the activity:</p>
            <table border="1" cellpadding="8" style="border-collapse: collapse; width: 100%; max-width: 600px;">
                <tr style="background-color: #f2f2f2;">
                    <th>Total Logins</th>
                    <td>{{ record['Total Logins'] }}</td>
                </tr>
                <tr>
                    <th>Unique Network Groups</th>
                    <td>{{ record['Unique Network Groups'] }}</td>
                </tr>
                <tr style="background-color: #f2f2f2;">
                    <th>Networks Found</th>
                    <td>{{ record['Networks Found'] }}</td>
                </tr>
                <tr>
                    <th>Segment Types</th>
                    <td>{{ record['Segment Types'] }}</td>
                </tr>
            </table>
            <p><b>Next Steps:</b></p>
            <ul>
                <li>If this was you (e.g., using different VPNs or travelling), please reply to this email to confirm.</li>
                <li>If you do not recognize this activity, please contact the IT Security team immediately to secure your account.</li>
            </ul>
            <p>Regards,<br><b>{{ sender_name }}</b></p>
        </body>
        </html>
        """)

        self.travel_template = Template("""
        <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <p>Dear {{ first_name }},</p>
            <p style="color: #d9534f; font-weight: bold;">URGENT: Impossible Travel Detected</p>
            <p>We detected multiple logins to your account from geographically distant locations in a timeframe that is physically impossible.</p>
            
            {% for find in findings %}
            <div style="border: 1px solid #ddd; padding: 10px; margin-bottom: 20px; border-left: 5px solid #d9534f;">
                <table border="1" cellpadding="8" style="border-collapse: collapse; width: 100%;">
                    <tr style="background-color: #f9f9f9;">
                        <th>Metric</th>
                        <th>Login Event A</th>
                        <th>Login Event B</th>
                    </tr>
                    <tr>
                        <td><b>IP Address</b></td>
                        <td>{{ find['IP 1'] }}</td>
                        <td>{{ find['IP 2'] }}</td>
                    </tr>
                    <tr>
                        <td><b>Location</b></td>
                        <td>{{ find['Location 1'] }}</td>
                        <td>{{ find['Location 2'] }}</td>
                    </tr>
                    <tr>
                        <td><b>Time</b></td>
                        <td>{{ find['Time 1'] }}</td>
                        <td>{{ find['Time 2'] }}</td>
                    </tr>
                </table>
                <p style="margin-top: 10px;">
                    <b>Distance:</b> {{ find['Physical Distance (km)'] }} km | 
                    <b>Time Delta:</b> {{ find['Time Passed (hrs)'] }} hours | 
                    <b>Min Required Time:</b> {{ find['Min Possible Travel Time (hrs)'] }} hours
                </p>
            </div>
            {% endfor %}

            <p><b>Action Required:</b> This pattern often indicates that your credentials may have been compromised. Please change your password immediately and contact IT Security at security-alerts@{{ email_domain }}.</p>
            <p>Regards,<br><b>{{ sender_name }}</b></p>
        </body>
        </html>
        """)

    def build_email_address(self, username):
        clean_user = username.strip()
        return f"{clean_user}@{self.email_domain}"

    def get_first_name(self, username):
        parts = username.split('.')
        return parts[0].capitalize()

    def strip_html(self, html):
        return re.sub('<[^<]+?>', '', html)

    def render_subnet_email(self, record):
        first_name = self.get_first_name(record['Username'])
        return self.subnet_template.render(
            first_name=first_name, 
            record=record, 
            sender_name=self.sender_name
        )

    def render_impossible_travel_email(self, username, findings):
        first_name = self.get_first_name(username)
        return self.travel_template.render(
            first_name=first_name, 
            findings=findings, 
            sender_name=self.sender_name,
            email_domain=self.email_domain
        )

    def send_email(self, to_address, subject, html_body):
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{self.sender_name} <{self.sender_email}>"
        msg['To'] = to_address
        if self.cc_security_team:
            msg['Cc'] = self.cc_security_team

        text_body = self.strip_html(html_body)
        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))

        recipients = [to_address]
        if self.cc_security_team:
            recipients.append(self.cc_security_team)

        if self.dry_run:
            print(f"[DRY RUN] Email to: {to_address}")
            print(f"[DRY RUN] Subject: {subject}")
            # print(f"[DRY RUN] Body Snippet: {html_body[:200]}...")
            return {'status': 'dry_run', 'to': to_address}

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as server:
                if self.use_tls:
                    server.starttls()
                if self.smtp_user and self.smtp_pass:
                    server.login(self.smtp_user, self.smtp_pass)
                server.sendmail(self.sender_email, recipients, msg.as_string())
            return {'status': 'sent', 'to': to_address}
        except Exception as e:
            return {'status': 'failed', 'to': to_address, 'error': str(e)}

    def dispatch_subnet_alerts(self, mismatch_data):
        results = []
        count = len(mismatch_data)
        for i, record in enumerate(mismatch_data):
            username = record['Username']
            to_addr = self.build_email_address(username)
            subject = f"Security Notification: Unusual Network Activity Detected (User: {username})"
            html = self.render_subnet_email(record)
            
            print(f"Sending subnet alert {i+1}/{count} to {to_addr}...")
            res = self.send_email(to_addr, subject, html)
            results.append(res)
        return results

    def dispatch_impossible_travel_alerts(self, impossible_travel_data):
        # Group by username
        grouped = {}
        for record in impossible_travel_data:
            user = record['Username']
            if user not in grouped:
                grouped[user] = []
            grouped[user].append(record)

        results = []
        count = len(grouped)
        for i, (username, findings) in enumerate(grouped.items()):
            to_addr = self.build_email_address(username)
            subject = f"URGENT: Impossible Travel Activity Detected (User: {username})"
            html = self.render_impossible_travel_email(username, findings)
            
            print(f"Sending impossible travel alert {i+1}/{count} to {to_addr}...")
            res = self.send_email(to_addr, subject, html)
            results.append(res)
        return results

    def dispatch_all(self, mismatch_data, impossible_travel_data):
        res_subnet = self.dispatch_subnet_alerts(mismatch_data)
        res_travel = self.dispatch_impossible_travel_alerts(impossible_travel_data)
        
        failed = [r for r in res_subnet + res_travel if r['status'] == 'failed']
        
        return {
            'subnet_alerts_sent': len([r for r in res_subnet if r['status'] in ('sent', 'dry_run')]),
            'travel_alerts_sent': len([r for r in res_travel if r['status'] in ('sent', 'dry_run')]),
            'failed': failed
        }
