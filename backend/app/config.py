PUBLIC_EMAIL_PROVIDERS = {
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "yahoo.co.il",
    "protonmail.com", "proton.me", "icloud.com", "live.com", "msn.com",
    "aol.com", "zoho.com", "mail.com", "yandex.com", "gmx.com",
    "walla.co.il", "bezeqint.net",
}

# Recruiting, scheduling, and email-delivery platforms that legitimately send
# email on behalf of other companies, so domain mismatch with the sender is expected.
ATS_AND_SAAS_DOMAINS = {
    # ATS / recruiting
    "greenhouse.io", "lever.co", "workable.com", "smartrecruiters.com",
    "jobvite.com", "icims.com", "taleo.net", "successfactors.com",
    "breezy.hr", "ashbyhq.com", "rippling.com", "comeet.com",
    # Scheduling
    "calendly.com", "cal.com",
    # Transactional / marketing email infrastructure
    "sendgrid.net", "mailgun.org", "sparkpostmail.com", "amazonses.com",
    "mailchimp.com", "klaviyo.com", "brevo.com", "sendpulse.com",
    "constantcontact.com", "campaignmonitor.com",
    # Document / e-signature
    "docusign.net", "docusign.com",
    # Common SaaS link destinations
    "salesforce.com", "hubspot.com", "zendesk.com", "intercom.io",
    "notion.so", "atlassian.net", "atlassian.com",
}

# Add domains here to suppress domain-mismatch warnings for your own infrastructure.
TRUSTED_COMPANY_DOMAINS: set = set()

# Email tracking and analytics domains used purely for open/click measurement.
# Links to these domains carry no content risk and should not count as suspicious
# external destinations in the mismatch check.
TRACKING_DOMAINS = {
    # Mailchimp click-tracking alias
    "list-manage.com", "mailchi.mp",
    # Salesforce / Pardot
    "pardot.com",
    # HubSpot sales tracking (Sidekick)
    "sidekickopen.com",
    # Customer.io
    "customer.io",
    # Yesware
    "yesware.com",
    # Salesloft
    "salesloft.com",
    # Outreach
    "outreach.io",
    # Mailtrack
    "mailtrack.io",
    # ActiveCampaign
    "activehosted.com",
    # Iterable
    "iterable.com",
    # ConvertKit
    "convertkit.com",
    # Drip
    "drip.com",
    # GetResponse
    "getresponse.com",
    # Branch deep-link tracking
    "app.link",
}
