from calendar import monthrange
from collections import Counter, defaultdict
from datetime import date, datetime
from io import BytesIO
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import urllib.parse
import uuid
import urllib.request
from xml.sax.saxutils import escape

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, session, url_for
from markupsafe import Markup, escape as html_escape
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Image as PlatypusImage, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from pypdf import PdfReader, PdfWriter
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY", "change-this-secret-key")

_URL_RE = re.compile(r"(https?://[^\s<>\"']+)")

@app.template_filter("linkify")
def linkify_filter(text):
    escaped = str(html_escape(text or ""))
    linked = _URL_RE.sub(
        r'<a href="\1" target="_blank" rel="noopener noreferrer">\1</a>',
        escaped,
    )
    return Markup(linked.replace("\n", "<br>"))
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_CACHE_TTL = 3600
_nvd_cache: dict = {}
DB_DIRECTORY = Path(__file__).resolve().parent / ".venv" / "data"
DB_PATH = DB_DIRECTORY / "software_auditor.db"
UPLOADS_DIR = Path(__file__).resolve().parent / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)
PDF_LOGO_PATH = Path(r"C:\Users\ggleeson\OneDrive - St Patricks College\Visual Studio Projects\Ticketpad\static\images\crest.png")
LOGIN_USERNAME = os.environ.get("APP_USERNAME", "admin")
LOGIN_PASSWORD_HASH = generate_password_hash(os.environ.get("APP_PASSWORD", "change-me"))

ASSESSMENT_FIELDS = (
    "software_name",
    "vendor_name",
    "software_description",
    "vendor_country",
    "software_website",
    "vendor_website",
    "terms_conditions_link",
    "license_agreement_link",
    "license_type",
    "subscription_billing_frequency",
    "version",
    "product_updates",
    "security_updates",
    "free_software",
    "currency_type",
    "license_cost",
    "purchase_link",
    "vendor_security_assessment",
    "student_intended_use",
    "age_restrictions",
    "allows_acceptance_on_behalf_of_entity",
    "terms_compliance_notes",
    "compatible_end_user_devices",
    "end_user_device_notes",
    "compatible_infrastructure",
    "infrastructure_notes",
    "supports_m365_sso",
    "integration_notes",
    "it_approved",
    "approval_date",
    "it_approval_notes",
    "student_consent_required",
    "student_consent_notes",
    "approver",
    "approver_date",
    "signed",
    "software_license_details",
    "license_start_date",
    "license_renewal_date",
    "deployment_groups",
    "deployment_date",
    "audit_reminder_frequency",
    "review_date",
    "next_audit_date",
    "submitted_date",
    "software_id",
    "is_assessment",
    "submission_status",
    "category",
    "unrelated_cves",
    "it_recommendation",
    "st4s_compliant",
    "essential_eight_compliant",
    "no_vendor_terms_conditions",
)

CHECKBOX_FIELDS = {
    "free_software",
    "product_updates",
    "security_updates",
    "no_vendor_terms_conditions",
}
VENDOR_PRIVACY_FIELDS = (
    "no_vendor_privacy_policy",
    "dpa_status",
    "data_storage_location",
    "storage_location_notes",
    "cloud_hosted_data",
    "data_types_stored",
    "privacy_laws_adhered_to",
    "privacy_law_notes",
    "security_privacy_standards",
    "sector_specific_contextual_laws",
    "cross_border_data_transfer_mechanisms",
    "us_specific_laws",
    "data_storage_notes",
    "privacy_notes",
)
VENDOR_PROFILE_FIELDS = (
    "vendor_name",
    "vendor_country",
    "vendor_website",
    "vendor_terms_conditions_link",
    "no_vendor_terms_conditions",
    "vendor_cookie_policy_link",
    "vendor_privacy_policy_link",
    "online_support",
    "vendor_audit_reminder_frequency",
    "vendor_next_audit_date",
    "vendor_age_restrictions",
    "vendor_terms_conditions_notes",
    "vendor_allows_acceptance_on_behalf_of_entity",
    "privacy_policy_pdf_filename",
    "privacy_policy_pdf_original_name",
    "vendor_tc_pdf_filename",
    "vendor_tc_pdf_original_name",
)
VENDOR_ASSESSMENT_FIELDS = (
    "vendor_name",
    "vendor_assessment_date",
    "vendor_security_assessment",
    *VENDOR_PRIVACY_FIELDS,
    "vendor_audit_reminder_frequency",
    "vendor_next_audit_date",
    "submitted_date",
    "submission_status",
)
DATA_TYPE_OPTIONS = (
    "Organisation name",
    "User legal names",
    "Username",
    "Date of birth",
    "User email addresses",
    "User role",
    "Academic Records",
    "Account preferences",
    "Phone number",
    "Physical or mailing address",
    "User IDs",
    "Account credentials",
    "Health information",
    "Parent or guardian contact details",
    "Photos or videos",
    "Financial information",
    "Product registrations and licenses",
    "Purchase and billing records",
    "Support communications",
    "Other personal information",
)
DATA_TYPE_LEGACY_MAP = {
    "Student names": "User legal names",
    "Staff names": "User legal names",
    "Student email addresses": "User email addresses",
    "Staff email addresses": "User email addresses",
    "Student IDs": "User IDs",
    "Academic records": "Academic Records",
    "Account credentials (stored securely and encrypted)": "Account credentials",
}
PRIVACY_LAW_LEGACY_MAP = {
    "GDPR": "GDPR / GDPR (EU)",
}
PRIVACY_LAW_OPTIONS = (
    "Australian Privacy Act 1988",
    "Australian Privacy Principles (APPs)",
    "GDPR / GDPR (EU)",
    "UK GDPR",
)
INTERNATIONAL_PRIVACY_LAW_OPTIONS = (
    "APPI (Japan)",
    "FDPA (Germany)",
    "LGPD (Brazil)",
    "New Zealand Privacy Act 2020",
    "PDPA (Singapore)",
    "PIPEDA (Canada)",
    "PIPA (South Korea)",
    "Swiss Federal Data Protection Act (FADP)",
)
SECURITY_PRIVACY_STANDARD_OPTIONS = (
    "ISO 9001",
    "ISO/IEC 27001",
    "ISO/IEC 27017",
    "ISO/IEC 27018",
    "ISO/IEC 27701",
    "ISO/IEC 42001",
    "BSI C5",
    "CSA CAIQ",
    "CSA STAR Level 1",
    "CSA STAR Level 2",
    "SOC 1",
    "SOC 2",
    "SOC 3",
    "NIST Cybersecurity Framework",
    "FedRAMP",
    "TISAX",
    "TX-RAMP",
    "APEC Privacy Framework (Asia-Pacific)",
    "PCI DSS",
    "CIS Controls",
    "VPAT 508",
)
SECTOR_SPECIFIC_CONTEXTUAL_LAW_OPTIONS = (
    "HIPAA",
    "FERPA",
    "SOX",
    "COPPA",
    "GLBA",
    "SOPIPA",
)
CROSS_BORDER_DATA_TRANSFER_MECHANISM_OPTIONS = (
    "EU Standard Contractual Clauses (SCCs)",
    "EU Adequacy Decisions",
    "EU-US Data Privacy Framework (DPF)",
    "International Data Transfer Agreement (UK)",
    "Binding Corporate Rules (BCRs)",
)
US_SPECIFIC_LAW_OPTIONS = (
    "CCPA / CPRA (California)",
    "VCDPA (Virginia)",
    "CPA (Colorado)",
    "CTDPA (Connecticut)",
)
COUNTRY_OPTIONS = (
    "Overseas (Unspecified)",
    "Afghanistan",
    "Albania",
    "Algeria",
    "Andorra",
    "Angola",
    "Antigua and Barbuda",
    "Argentina",
    "Armenia",
    "Australia",
    "Austria",
    "Azerbaijan",
    "Bahamas",
    "Bahrain",
    "Bangladesh",
    "Barbados",
    "Belarus",
    "Belgium",
    "Belize",
    "Benin",
    "Bhutan",
    "Bolivia",
    "Bosnia and Herzegovina",
    "Botswana",
    "Brazil",
    "Brunei",
    "Bulgaria",
    "Burkina Faso",
    "Burundi",
    "Cabo Verde",
    "Cambodia",
    "Cameroon",
    "Canada",
    "Central African Republic",
    "Chad",
    "Chile",
    "China",
    "Colombia",
    "Comoros",
    "Congo",
    "Costa Rica",
    "Croatia",
    "Cuba",
    "Cyprus",
    "Czech Republic",
    "Denmark",
    "Djibouti",
    "Dominica",
    "Dominican Republic",
    "Ecuador",
    "Egypt",
    "El Salvador",
    "Equatorial Guinea",
    "Eritrea",
    "Estonia",
    "Eswatini",
    "Ethiopia",
    "Fiji",
    "Finland",
    "France",
    "Gabon",
    "Gambia",
    "Georgia",
    "Germany",
    "Ghana",
    "Greece",
    "Grenada",
    "Guatemala",
    "Guinea",
    "Guinea-Bissau",
    "Guyana",
    "Haiti",
    "Honduras",
    "Hungary",
    "Iceland",
    "India",
    "Indonesia",
    "Iran",
    "Iraq",
    "Ireland",
    "Israel",
    "Italy",
    "Jamaica",
    "Japan",
    "Jordan",
    "Kazakhstan",
    "Kenya",
    "Kiribati",
    "Kuwait",
    "Kyrgyzstan",
    "Laos",
    "Latvia",
    "Lebanon",
    "Lesotho",
    "Liberia",
    "Libya",
    "Liechtenstein",
    "Lithuania",
    "Luxembourg",
    "Madagascar",
    "Malawi",
    "Malaysia",
    "Maldives",
    "Mali",
    "Malta",
    "Marshall Islands",
    "Mauritania",
    "Mauritius",
    "Mexico",
    "Micronesia",
    "Moldova",
    "Monaco",
    "Mongolia",
    "Montenegro",
    "Morocco",
    "Mozambique",
    "Myanmar",
    "Namibia",
    "Nauru",
    "Nepal",
    "Netherlands",
    "New Zealand",
    "Nicaragua",
    "Niger",
    "Nigeria",
    "North Korea",
    "North Macedonia",
    "Norway",
    "Oman",
    "Pakistan",
    "Palau",
    "Panama",
    "Papua New Guinea",
    "Paraguay",
    "Peru",
    "Philippines",
    "Poland",
    "Portugal",
    "Qatar",
    "Romania",
    "Russia",
    "Rwanda",
    "Saint Kitts and Nevis",
    "Saint Lucia",
    "Saint Vincent and the Grenadines",
    "Samoa",
    "San Marino",
    "Sao Tome and Principe",
    "Saudi Arabia",
    "Senegal",
    "Serbia",
    "Seychelles",
    "Sierra Leone",
    "Singapore",
    "Slovakia",
    "Slovenia",
    "Solomon Islands",
    "Somalia",
    "South Africa",
    "South Korea",
    "South Sudan",
    "Spain",
    "Sri Lanka",
    "Sudan",
    "Suriname",
    "Sweden",
    "Switzerland",
    "Syria",
    "Taiwan",
    "Tajikistan",
    "Tanzania",
    "Thailand",
    "Timor-Leste",
    "Togo",
    "Tonga",
    "Trinidad and Tobago",
    "Tunisia",
    "Turkey",
    "Turkmenistan",
    "Tuvalu",
    "Uganda",
    "Ukraine",
    "United Arab Emirates",
    "United Kingdom",
    "United States",
    "Uruguay",
    "Uzbekistan",
    "Vanuatu",
    "Vatican City",
    "Venezuela",
    "Vietnam",
    "Yemen",
    "Zambia",
    "Zimbabwe",
)
COUNTRY_MAP_COORDINATES = {
    "Afghanistan": (33.9, 67.7),
    "Albania": (41.2, 20.2),
    "Algeria": (28.0, 1.7),
    "Andorra": (42.5, 1.6),
    "Angola": (-11.2, 17.9),
    "Antigua and Barbuda": (17.1, -61.8),
    "Argentina": (-38.4, -63.6),
    "Armenia": (40.1, 45.0),
    "Australia": (-25.3, 133.8),
    "Austria": (47.5, 14.6),
    "Azerbaijan": (40.1, 47.6),
    "Bahamas": (25.0, -77.4),
    "Bahrain": (26.1, 50.6),
    "Bangladesh": (23.7, 90.4),
    "Barbados": (13.2, -59.5),
    "Belarus": (53.7, 27.9),
    "Belgium": (50.5, 4.5),
    "Belize": (17.2, -88.5),
    "Benin": (9.3, 2.3),
    "Bhutan": (27.5, 90.4),
    "Bolivia": (-16.3, -63.6),
    "Bosnia and Herzegovina": (44.2, 17.7),
    "Botswana": (-22.3, 24.7),
    "Brazil": (-14.2, -51.9),
    "Brunei": (4.5, 114.7),
    "Bulgaria": (42.7, 25.5),
    "Burkina Faso": (12.2, -1.6),
    "Burundi": (-3.4, 29.9),
    "Cabo Verde": (16.0, -24.0),
    "Cambodia": (12.6, 105.0),
    "Cameroon": (7.4, 12.4),
    "Canada": (56.1, -106.3),
    "Central African Republic": (6.6, 20.9),
    "Chad": (15.5, 18.7),
    "Chile": (-35.7, -71.5),
    "China": (35.9, 104.2),
    "Colombia": (4.6, -74.3),
    "Comoros": (-11.9, 43.9),
    "Congo": (-0.2, 15.8),
    "Costa Rica": (9.7, -83.8),
    "Croatia": (45.1, 15.2),
    "Cuba": (21.5, -79.4),
    "Cyprus": (35.1, 33.4),
    "Czech Republic": (49.8, 15.5),
    "Denmark": (56.3, 9.5),
    "Djibouti": (11.8, 42.6),
    "Dominica": (15.4, -61.4),
    "Dominican Republic": (18.7, -70.2),
    "Ecuador": (-1.8, -78.2),
    "Egypt": (26.8, 30.8),
    "El Salvador": (13.8, -88.9),
    "Equatorial Guinea": (1.7, 10.3),
    "Eritrea": (15.2, 39.8),
    "Estonia": (58.6, 25.0),
    "Eswatini": (-26.5, 31.5),
    "Ethiopia": (9.1, 40.5),
    "Fiji": (-17.7, 178.1),
    "Finland": (61.9, 25.7),
    "France": (46.2, 2.2),
    "Gabon": (-0.8, 11.6),
    "Gambia": (13.4, -15.3),
    "Georgia": (42.3, 43.4),
    "Germany": (51.2, 10.5),
    "Ghana": (7.9, -1.0),
    "Greece": (39.1, 21.8),
    "Grenada": (12.1, -61.7),
    "Guatemala": (15.8, -90.2),
    "Guinea": (9.9, -9.7),
    "Guinea-Bissau": (11.8, -15.2),
    "Guyana": (5.0, -58.9),
    "Haiti": (19.0, -72.3),
    "Honduras": (15.2, -86.2),
    "Hungary": (47.2, 19.5),
    "Iceland": (64.9, -18.7),
    "India": (20.6, 78.9),
    "Indonesia": (-0.8, 113.9),
    "Iran": (32.4, 53.7),
    "Iraq": (33.2, 43.7),
    "Ireland": (53.4, -8.2),
    "Israel": (31.0, 35.0),
    "Italy": (41.9, 12.6),
    "Jamaica": (18.1, -77.3),
    "Japan": (36.2, 138.3),
    "Jordan": (31.2, 36.2),
    "Kazakhstan": (48.0, 66.9),
    "Kenya": (0.0, 37.9),
    "Kiribati": (1.9, -157.4),
    "Kuwait": (29.3, 47.5),
    "Kyrgyzstan": (41.2, 74.8),
    "Laos": (19.9, 102.5),
    "Latvia": (56.9, 24.6),
    "Lebanon": (33.9, 35.9),
    "Lesotho": (-29.6, 28.2),
    "Liberia": (6.4, -9.4),
    "Libya": (26.3, 17.2),
    "Liechtenstein": (47.2, 9.6),
    "Lithuania": (55.2, 23.9),
    "Luxembourg": (49.8, 6.1),
    "Madagascar": (-18.8, 46.9),
    "Malawi": (-13.3, 34.3),
    "Malaysia": (4.2, 101.9),
    "Maldives": (3.2, 73.2),
    "Mali": (17.6, -4.0),
    "Malta": (35.9, 14.4),
    "Marshall Islands": (7.1, 171.2),
    "Mauritania": (21.0, -10.9),
    "Mauritius": (-20.3, 57.6),
    "Mexico": (23.6, -102.6),
    "Micronesia": (7.4, 150.6),
    "Moldova": (47.4, 28.4),
    "Monaco": (43.7, 7.4),
    "Mongolia": (46.9, 103.8),
    "Montenegro": (42.7, 19.3),
    "Morocco": (31.8, -7.1),
    "Mozambique": (-18.7, 35.5),
    "Myanmar": (21.9, 95.9),
    "Namibia": (-23.0, 18.5),
    "Nauru": (-0.5, 166.9),
    "Nepal": (28.4, 84.1),
    "Netherlands": (52.1, 5.3),
    "New Zealand": (-40.9, 174.9),
    "Nicaragua": (12.9, -85.2),
    "Niger": (17.6, 8.1),
    "Nigeria": (9.1, 8.7),
    "North Korea": (40.3, 127.5),
    "North Macedonia": (41.6, 21.7),
    "Norway": (60.5, 8.5),
    "Oman": (21.5, 55.9),
    "Pakistan": (30.4, 69.3),
    "Palau": (7.5, 134.6),
    "Panama": (8.5, -80.8),
    "Papua New Guinea": (-6.3, 143.9),
    "Paraguay": (-23.4, -58.4),
    "Peru": (-9.2, -75.0),
    "Philippines": (12.9, 121.8),
    "Poland": (51.9, 19.1),
    "Portugal": (39.4, -8.2),
    "Qatar": (25.4, 51.2),
    "Romania": (45.9, 24.9),
    "Russia": (61.5, 105.3),
    "Rwanda": (-1.9, 29.9),
    "Saint Kitts and Nevis": (17.4, -62.8),
    "Saint Lucia": (13.9, -61.0),
    "Saint Vincent and the Grenadines": (13.3, -61.2),
    "Samoa": (-13.8, -172.1),
    "San Marino": (43.9, 12.5),
    "Sao Tome and Principe": (0.2, 6.6),
    "Saudi Arabia": (23.9, 45.1),
    "Senegal": (14.5, -14.5),
    "Serbia": (44.0, 20.9),
    "Seychelles": (-4.7, 55.5),
    "Sierra Leone": (8.5, -11.8),
    "Singapore": (1.4, 103.8),
    "Slovakia": (48.7, 19.7),
    "Slovenia": (46.2, 14.9),
    "Solomon Islands": (-9.6, 160.2),
    "Somalia": (5.2, 46.2),
    "South Africa": (-30.6, 22.9),
    "South Korea": (35.9, 127.8),
    "South Sudan": (7.9, 30.0),
    "Spain": (40.5, -3.7),
    "Sri Lanka": (7.9, 80.8),
    "Sudan": (12.9, 30.2),
    "Suriname": (3.9, -56.0),
    "Sweden": (60.1, 18.6),
    "Switzerland": (46.8, 8.2),
    "Syria": (34.8, 39.0),
    "Taiwan": (23.7, 121.0),
    "Tajikistan": (38.9, 71.0),
    "Tanzania": (-6.4, 34.9),
    "Thailand": (15.9, 100.9),
    "Timor-Leste": (-8.9, 125.7),
    "Togo": (8.6, 0.8),
    "Tonga": (-21.2, -175.2),
    "Trinidad and Tobago": (10.7, -61.2),
    "Tunisia": (33.9, 9.5),
    "Turkey": (39.0, 35.2),
    "Turkmenistan": (39.0, 59.6),
    "Tuvalu": (-7.1, 177.6),
    "Uganda": (1.4, 32.3),
    "Ukraine": (48.4, 31.2),
    "United Arab Emirates": (24.0, 54.0),
    "United Kingdom": (55.4, -3.4),
    "United States": (39.8, -98.6),
    "Uruguay": (-32.5, -55.8),
    "Uzbekistan": (41.4, 64.6),
    "Vanuatu": (-15.4, 166.9),
    "Vatican City": (41.9, 12.5),
    "Venezuela": (6.4, -66.6),
    "Vietnam": (14.1, 108.3),
    "Yemen": (15.6, 48.5),
    "Zambia": (-13.1, 27.8),
    "Zimbabwe": (-19.0, 29.2),
}

PDF_FIELD_LABELS = {
    "software_name": "Software Name",
    "vendor_name": "Vendor Name",
    "software_description": "Software Description",
    "vendor_country": "Vendor Country",
    "software_website": "Software Website",
    "software_support": "Software Support",
    "vendor_website": "Vendor Website",
    "vendor_terms_conditions_link": "Vendor Terms and Conditions Link",
    "terms_conditions_link": "Terms and Conditions Link",
    "vendor_privacy_policy_link": "Vendor Privacy Policy Link",
    "license_agreement_link": "License Agreement Link",
    "license_type": "License Type",
    "subscription_billing_frequency": "Subscription Billing Frequency",
    "version": "Version",
    "free_software": "Free Software",
    "license_cost": "License Cost",
    "purchase_link": "Purchase Link",
    "data_storage_location": "Data Storage Location",
    "dpa_status": "DPA Status",
    "storage_location_notes": "Storage Location Notes",
    "cloud_hosted_data": "Cloud-Hosted Data",
    "data_types_stored": "Data Types Hosted by Vendor",
    "privacy_laws_adhered_to": "Privacy Laws Adhered To",
    "privacy_law_notes": "Privacy Law Notes",
    "security_privacy_standards": "Security & Privacy Standards",
    "sector_specific_contextual_laws": "Sector-Specific or Contextual Laws",
    "cross_border_data_transfer_mechanisms": "Cross-Border Data Transfer Mechanisms",
    "us_specific_laws": "US-Specific Laws",
    "data_storage_notes": "Data Storage Notes",
    "privacy_notes": "Privacy Standards Notes",
    "vendor_security_assessment": "Vendor Security Assessment",
    "product_updates": "Product Updates",
    "security_updates": "Security Updates",
    "support_notes": "Support Notes",
    "student_intended_use": "Software Intended for Student Use",
    "age_restrictions": "Age Restrictions",
    "allows_acceptance_on_behalf_of_entity": "Terms Permit Acceptance by the College on Behalf of Students",
    "terms_compliance_notes": "Terms Compliance Notes",
    "compatible_end_user_devices": "Compatible End-user Devices",
    "end_user_device_notes": "End-user Device Notes",
    "compatible_infrastructure": "Compatible Infrastructure",
    "infrastructure_notes": "Infrastructure Notes",
    "supports_m365_sso": "Supports Microsoft 365 SSO",
    "integration_notes": "Integration Notes",
    "it_approved": "IT Approved",
    "approval_date": "Approval Date",
    "it_approval_notes": "IT Approval Notes",
    "student_consent_required": "Student Consent Required",
    "student_consent_notes": "Student Consent Notes",
    "approver": "Approver",
    "approver_date": "Approver Date",
    "signed": "Signed",
    "software_license_details": "Software License Details",
    "license_start_date": "License Date",
    "license_renewal_date": "License Renewal Date",
    "deployment_type": "Deployment Type",
    "tested": "Tested",
    "deployed": "Active",
    "deployment_date": "Deployment Date",
    "audit_reminder_frequency": "Audit Reminder Schedule",
    "review_date": "Review Date",
    "next_audit_date": "Next Audit Date",
    "risk_level": "Risk Level",
    "it_recommendation": "IT Recommendation",
    "st4s_compliant": "ST4S Compliance",
    "essential_eight_compliant": "Essential 8 Compliance",
}

PDF_SECTION_FIELDS = [
    ("Software Information", [
        "software_name",
        "software_description",
        "software_website",
        "version",
        "license_cost",
        "purchase_link",
        "product_updates",
        "security_updates",
        "support_notes",
        "license_start_date",
        "license_renewal_date",
        "deployment_date",
        "next_audit_date",
    ]),
    ("Vendor Information", [
        "vendor_name",
        "vendor_country",
        "vendor_website",
        "terms_conditions_link",
        "vendor_privacy_policy_link",
        "vendor_security_assessment",
        "data_storage_location",
        "dpa_status",
        "storage_location_notes",
        "cloud_hosted_data",
        "data_types_stored",
        "privacy_laws_adhered_to",
        "sector_specific_contextual_laws",
        "cross_border_data_transfer_mechanisms",
        "us_specific_laws",
        "privacy_law_notes",
        "security_privacy_standards",
        "data_storage_notes",
        "privacy_notes",
    ]),
    ("Assessment Responses", [
        "assessment_date",
        "license_type",
        "subscription_billing_frequency",
        "student_intended_use",
        "age_restrictions",
        "allows_acceptance_on_behalf_of_entity",
        "terms_compliance_notes",
        "compatible_end_user_devices",
        "end_user_device_notes",
        "compatible_infrastructure",
        "infrastructure_notes",
        "supports_m365_sso",
        "integration_notes",
        "st4s_compliant",
        "essential_eight_compliant",
        "risk_level",
    ]),
]
PDF_HIDDEN_FIELDS = set()

REMINDER_MONTHS = {
    "6_months": 6,
    "1_year": 12,
    "2_years": 24,
}

MULTI_SELECT_FIELDS = {
    "data_types_stored",
    "privacy_laws_adhered_to",
    "security_privacy_standards",
    "sector_specific_contextual_laws",
    "cross_border_data_transfer_mechanisms",
    "us_specific_laws",
}

EU_COUNTRY_OPTIONS = (
    "Austria",
    "Belgium",
    "Bulgaria",
    "Croatia",
    "Cyprus",
    "Czech Republic",
    "Denmark",
    "Estonia",
    "Finland",
    "France",
    "Germany",
    "Greece",
    "Hungary",
    "Ireland",
    "Italy",
    "Latvia",
    "Lithuania",
    "Luxembourg",
    "Malta",
    "Netherlands",
    "Poland",
    "Portugal",
    "Romania",
    "Slovakia",
    "Slovenia",
    "Spain",
    "Sweden",
)
EEA_COUNTRY_OPTIONS = (
    *EU_COUNTRY_OPTIONS,
    "Iceland",
    "Liechtenstein",
    "Norway",
)
OTHER_DATA_STORAGE_LOCATION = "Other countries (unspecified)"
DATA_STORAGE_LOCATION_OPTIONS = COUNTRY_OPTIONS + (OTHER_DATA_STORAGE_LOCATION,)
DATA_STORAGE_COUNTRY_GROUPS = (
    ("EU", EU_COUNTRY_OPTIONS),
    ("EEA", EEA_COUNTRY_OPTIONS),
)

SOFTWARE_DETAIL_FIELDS = (
    "software_name",
    "vendor_name",
    "software_description",
    "vendor_country",
    "software_website",
    "software_support",
    "purchase_link",
    "product_updates",
    "security_updates",
    "support_notes",
    "license_start_date",
    "license_renewal_date",
    "deployment_groups",
    "deployment_type",
    "software_type",
    "tested",
    "deployment_date",
    "audit_reminder_frequency",
    "next_audit_date",
    "risk_level",
    "category",
)

FORM_OPTION_CONTEXT = {
    "country_options": COUNTRY_OPTIONS,
    "eu_country_options": EU_COUNTRY_OPTIONS,
    "eea_country_options": EEA_COUNTRY_OPTIONS,
    "data_type_options": DATA_TYPE_OPTIONS,
    "privacy_law_options": PRIVACY_LAW_OPTIONS,
    "international_privacy_law_options": INTERNATIONAL_PRIVACY_LAW_OPTIONS,
    "security_privacy_standard_options": SECURITY_PRIVACY_STANDARD_OPTIONS,
    "sector_specific_contextual_law_options": SECTOR_SPECIFIC_CONTEXTUAL_LAW_OPTIONS,
    "cross_border_data_transfer_mechanism_options": CROSS_BORDER_DATA_TRANSFER_MECHANISM_OPTIONS,
    "us_specific_law_options": US_SPECIFIC_LAW_OPTIONS,
}


def blank_assessment():
    record = {field: False if field in CHECKBOX_FIELDS else "" for field in ASSESSMENT_FIELDS}
    record["audit_reminder_frequency"] = "1_year"
    record["is_assessment"] = False
    record["submission_status"] = ""
    return record


def build_prefilled_assessment(source_record=None):
    assessment = blank_assessment()
    if source_record is None:
        return assessment

    for field in ASSESSMENT_FIELDS:
        if field == "review_date":
            continue
        assessment[field] = source_record.get(field, assessment[field])

    assessment["approval_date"] = ""
    assessment["approver_date"] = ""
    return assessment


def collect_software_form_data(form):
    license_type = form.get("license_type", "").strip()
    license_renewal_date = form.get("license_renewal_date", "").strip()
    if license_type == "Perpetual":
        license_renewal_date = ""

    return {
        "software_name": form.get("software_name", "").strip(),
        "vendor_name": form.get("vendor_name", "").strip(),
        "software_description": form.get("software_description", "").strip(),
        "vendor_country": form.get("vendor_country", "").strip(),
        "software_website": form.get("software_website", "").strip(),
        "software_support": form.get("software_support", "").strip(),
        "terms_conditions_link": form.get("terms_conditions_link", "").strip(),
        "license_agreement_link": form.get("license_agreement_link", "").strip(),
        "license_type": license_type,
        "purchase_link": form.get("purchase_link", "").strip(),
        "product_updates": "product_updates" in form,
        "security_updates": "security_updates" in form,
        "support_notes": form.get("support_notes", "").strip(),
        "license_start_date": form.get("license_start_date", "").strip(),
        "license_renewal_date": license_renewal_date,
        "deployment_groups": form.get("deployment_groups", "").strip(),
        "deployment_type": form.get("deployment_type", "").strip(),
        "software_type": form.get("software_type", "").strip(),
        "tested": "tested" in form,
        "deployment_date": form.get("deployment_date", "").strip(),
        "audit_reminder_frequency": form.get("audit_reminder_frequency", "").strip() or "1_year",
        "next_audit_date": form.get("next_audit_date", "").strip(),
        "category": form.get("category", "").strip(),
    }


def determine_assessment_date(record, fallback_date=None):
    candidate_dates = [
        record.get("submitted_date", ""),
        record.get("assessment_date", ""),
    ]
    for candidate in candidate_dates:
        try:
            return datetime.strptime(candidate, "%Y-%m-%d").date().isoformat()
        except ValueError:
            continue
    if not record.get("is_assessment"):
        return ""
    return ""


def get_vendor_backed_value(record, field):
    vendor_name = normalized_name(record.get("vendor_name", ""))
    if vendor_name:
        vendor_assessments = [
            assessment for assessment in globals().get("VENDOR_ASSESSMENT_RECORDS", [])
            if normalized_name(assessment.get("vendor_name", "")) == vendor_name
        ]
        latest_assessment = sorted(
            vendor_assessments,
            key=lambda assessment: (
                assessment.get("vendor_assessment_date", ""),
                assessment.get("submitted_date", ""),
                assessment.get("id", 0),
            ),
            reverse=True,
        )
        if latest_assessment:
            return latest_assessment[0].get(field, "") or record.get(field, "")
    return record.get(field, "")


def enrich_assessment(record):
    risk_level = record.get("risk_level", "")

    if record.get("deployed"):
        deployment_stage = "Production"
    elif record.get("tested"):
        deployment_stage = "Pilot"
    else:
        deployment_stage = "Planned"

    enriched = dict(record)
    enriched["review_date"] = calculate_review_date(
        record.get("deployment_date", ""),
        record.get("audit_reminder_frequency", ""),
        record.get("review_date", ""),
    )
    enriched["risk_level"] = risk_level
    enriched["deployment_stage"] = deployment_stage
    enriched["assessment_date"] = determine_assessment_date(record)
    if record.get("submission_status") == "submitted" and not enriched.get("submitted_date"):
        enriched["submitted_date"] = enriched["assessment_date"]
    return enriched


def is_submitted_assessment(record):
    return bool(record.get("is_assessment")) and record.get("submission_status") == "submitted"


def is_submitted_vendor_assessment(record):
    return record.get("submission_status") == "submitted"


def normalized_name(value):
    return str(value).strip().casefold()


def add_months_to_date(base_date, months):
    month_index = base_date.month - 1 + months
    year = base_date.year + month_index // 12
    month = month_index % 12 + 1

    day = min(base_date.day, monthrange(year, month)[1])
    return base_date.replace(year=year, month=month, day=day)


def calculate_review_date(deployment_date, audit_reminder_frequency, fallback_review_date=""):
    if fallback_review_date:
        return fallback_review_date

    if not deployment_date or not audit_reminder_frequency:
        return fallback_review_date

    months = REMINDER_MONTHS.get(audit_reminder_frequency)
    if months is None:
        return fallback_review_date

    try:
        base_date = datetime.strptime(deployment_date, "%Y-%m-%d").date()
    except ValueError:
        return fallback_review_date

    return add_months_to_date(base_date, months).isoformat()


def calculate_next_audit_date_from_assessment(assessment_date, audit_reminder_frequency):
    months = REMINDER_MONTHS.get(audit_reminder_frequency)
    if months is None:
        return ""

    try:
        base_date = datetime.strptime(assessment_date, "%Y-%m-%d").date()
    except ValueError:
        return ""

    return add_months_to_date(base_date, months).isoformat()


def normalize_submitted_audit_dates(record):
    if not is_submitted_assessment(record):
        return

    calculated_next_audit_date = calculate_next_audit_date_from_assessment(
        record.get("assessment_date", ""),
        record.get("audit_reminder_frequency", ""),
    )
    if not calculated_next_audit_date:
        return

    current_next_audit_date = record.get("next_audit_date", "")
    try:
        assessment_date = datetime.strptime(record.get("assessment_date", ""), "%Y-%m-%d").date()
        current_audit_date = datetime.strptime(current_next_audit_date, "%Y-%m-%d").date()
    except ValueError:
        current_audit_date = None
    else:
        if current_audit_date > assessment_date:
            return

    record["next_audit_date"] = calculated_next_audit_date
    record["review_date"] = calculated_next_audit_date


def describe_overdue_duration(overdue_days):
    if overdue_days <= 0:
        return ""

    years = overdue_days // 365
    remainder = overdue_days % 365
    months = remainder // 30
    days = remainder % 30

    parts = []
    if years:
        parts.append(f"{years} year" + ("" if years == 1 else "s"))
    if months:
        parts.append(f"{months} month" + ("" if months == 1 else "s"))
    if days and not years:
        parts.append(f"{days} day" + ("" if days == 1 else "s"))

    if not parts:
        parts.append(f"{overdue_days} day" + ("" if overdue_days == 1 else "s"))

    return ", ".join(parts[:2])


def normalize_license_cost(value):
    cleaned = str(value).strip()
    if not cleaned:
        return ""

    try:
        amount = float(cleaned)
    except ValueError:
        return ""

    if amount < 0:
        return ""
    return f"{amount:.2f}"


def normalize_data_types_stored(value):
    return unique_values(value, mapper=lambda item: DATA_TYPE_LEGACY_MAP.get(item, item))


def get_selected_values(value):
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [str(item).strip() for item in value if str(item).strip()]


def unique_values(value, mapper=None, allowed_values=None):
    normalized_items = []
    seen = set()
    allowed_values = set(allowed_values or ())
    for item in get_selected_values(value):
        mapped_item = mapper(item) if mapper else item
        if allowed_values and mapped_item not in allowed_values:
            continue
        if mapped_item in seen:
            continue
        normalized_items.append(mapped_item)
        seen.add(mapped_item)

    return ", ".join(normalized_items)


def normalize_data_storage_locations(value):
    return unique_values(value, allowed_values=(*COUNTRY_OPTIONS, OTHER_DATA_STORAGE_LOCATION))


def get_home_country():
    home_country = APP_SETTINGS.get("home_country", "").strip()
    if home_country in COUNTRY_OPTIONS:
        return home_country
    return DEFAULT_APP_SETTINGS["home_country"]


def normalize_country_risk_assignments(value):
    if isinstance(value, str):
        try:
            parsed_value = json.loads(value) if value.strip() else {}
        except json.JSONDecodeError:
            parsed_value = {}
    elif isinstance(value, dict):
        parsed_value = value
    else:
        parsed_value = {}

    normalized = {}
    for country, risk_level in parsed_value.items():
        cleaned_country = str(country).strip()
        cleaned_risk_level = str(risk_level).strip()
        if cleaned_country not in COUNTRY_OPTIONS:
            continue
        if cleaned_risk_level not in RISK_CATEGORY_OPTIONS:
            continue
        normalized[cleaned_country] = cleaned_risk_level

    return dict(sorted(normalized.items(), key=lambda item: item[0]))


def get_country_risk_assignments():
    settings_assignments = normalize_country_risk_assignments(APP_SETTINGS.get("country_risk_assignments", "{}"))
    log_assignments = get_all_country_risk_from_log()
    return {**settings_assignments, **log_assignments}


def get_country_risk_level(country_name):
    return get_country_risk_assignments().get(str(country_name).strip(), "")


def get_all_country_risk_from_log():
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT country, risk_level FROM country_risk_comments "
            "WHERE id IN (SELECT MAX(id) FROM country_risk_comments GROUP BY country)"
        ).fetchall()
    return {row["country"]: row["risk_level"] for row in rows}


def get_country_risk_comments(country_name):
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT id, risk_level, comment, created_at FROM country_risk_comments "
            "WHERE country = ? ORDER BY created_at DESC, id DESC",
            (country_name,),
        ).fetchall()
    return [dict(row) for row in rows]


def normalize_signatory_alerts(value):
    if isinstance(value, str):
        try:
            parsed = json.loads(value) if value.strip() else {}
        except json.JSONDecodeError:
            parsed = {}
    elif isinstance(value, dict):
        parsed = value
    else:
        parsed = {}
    valid_alerts = set(PDF_ALERT_LABELS)
    return {
        role: [a for a in parsed.get(role, []) if a in valid_alerts]
        for role in SIGNATORY_ROLES
    }


def get_signatory_alerts():
    return normalize_signatory_alerts(APP_SETTINGS.get("signatory_alerts", "{}"))


def normalize_alert_risk_levels(value):
    if isinstance(value, str):
        try:
            parsed = json.loads(value) if value.strip() else {}
        except json.JSONDecodeError:
            parsed = {}
    elif isinstance(value, dict):
        parsed = value
    else:
        parsed = {}
    valid_alerts = set(PDF_ALERT_LABELS)
    return {
        key: str(level).strip()
        for key, level in parsed.items()
        if key in valid_alerts and str(level).strip() in RISK_CATEGORY_OPTIONS
    }


def get_alert_risk_levels():
    return normalize_alert_risk_levels(APP_SETTINGS.get("alert_risk_levels", "{}"))


def normalize_alert_pdf_visibility(value):
    if isinstance(value, str):
        try:
            parsed = json.loads(value) if value.strip() else {}
        except json.JSONDecodeError:
            parsed = {}
    elif isinstance(value, dict):
        parsed = value
    else:
        parsed = {}
    valid_alerts = set(PDF_ALERT_LABELS)
    return {key: bool(val) for key, val in parsed.items() if key in valid_alerts}


def get_alert_pdf_visibility():
    stored = normalize_alert_pdf_visibility(APP_SETTINGS.get("alert_pdf_visibility", "{}"))
    return {key: stored.get(key, True) for key in PDF_ALERT_LABELS}


def compute_software_alert_keys(record, vendor_record, vendor_map, home_country, item=None):
    """Returns the set of PDF_ALERT_LABELS keys that currently fire for a software item."""
    item = item or {}
    vendor_record = vendor_record or {}
    vendor_name = record.get("vendor_name", "")
    is_assessment = bool(record.get("is_assessment", False))

    product_updates = bool(item.get("product_updates", record.get("product_updates", False)))
    security_updates = bool(item.get("security_updates", record.get("security_updates", False)))
    tested = bool(item.get("tested", record.get("tested", False)))
    software_type = item.get("software_type", record.get("software_type", ""))
    category = item.get("category", record.get("category", ""))

    alert_keys = set()

    if not category:
        alert_keys.add("no_category")

    terms_link = record.get("terms_conditions_link", "")
    vendor_terms_link = vendor_record.get("vendor_terms_conditions_link", "")
    if vendor_name and not terms_link and not vendor_terms_link:
        alert_keys.add("no_tc")

    if terms_link:
        effective_age = record.get("age_restrictions", "")
        effective_acceptance = record.get("allows_acceptance_on_behalf_of_entity", "")
    else:
        effective_age = record.get("age_restrictions", "") or vendor_record.get("vendor_age_restrictions", "")
        effective_acceptance = (
            record.get("allows_acceptance_on_behalf_of_entity", "")
            or vendor_record.get("vendor_allows_acceptance_on_behalf_of_entity", "")
        )
    if effective_age and effective_age != "None" and effective_acceptance == "No":
        alert_keys.add("age_restriction")

    if vendor_map.get("high_risk_locations"):
        alert_keys.add("high_risk_locations")

    if vendor_name and not vendor_record.get("online_support", ""):
        alert_keys.add("no_support")

    if OTHER_DATA_STORAGE_LOCATION in vendor_map.get("locations", []):
        alert_keys.add("unspecified_locations")

    if vendor_map.get("no_privacy_policy"):
        alert_keys.add("no_privacy_policy")

    non_home_storage = [loc for loc in vendor_map.get("locations", []) if loc != home_country]
    if non_home_storage and vendor_map.get("dpa_status") == "Not Obtained":
        alert_keys.add("dpa_not_obtained")

    if vendor_map.get("dpa_status") == "Obtained":
        alert_keys.add("app_collection_notice")

    if is_assessment and not tested:
        alert_keys.add("not_tested")

    if is_assessment and not product_updates and software_type != "SaaS":
        alert_keys.add("no_product_updates")
    if is_assessment and not security_updates and software_type != "SaaS":
        alert_keys.add("no_security_updates")

    sso = record.get("supports_m365_sso", "")
    if sso in ("No SSO", "Third Party IdP"):
        alert_keys.add("sso")

    if is_assessment and not record.get("it_recommendation", ""):
        alert_keys.add("no_it_recommendation")

    if is_assessment and not record.get("st4s_compliant", ""):
        alert_keys.add("st4s_not_assessed")

    if is_assessment and not record.get("essential_eight_compliant", ""):
        alert_keys.add("essential_eight_not_assessed")

    return alert_keys


def highest_risk_from_alerts(alert_keys):
    """Returns the highest risk level configured for the given set of alert keys."""
    risk_order = {level: idx for idx, level in enumerate(RISK_CATEGORY_OPTIONS)}
    alert_risk_levels = get_alert_risk_levels()
    highest = ""
    highest_idx = -1
    for key in alert_keys:
        level = alert_risk_levels.get(key, "")
        if level in risk_order and risk_order[level] > highest_idx:
            highest = level
            highest_idx = risk_order[level]
    return highest


def is_dark_mode_enabled():
    return str(APP_SETTINGS.get("dark_mode", "false")).strip().lower() == "true"


def is_category_required():
    return str(APP_SETTINGS.get("category_required", "true")).strip().lower() == "true"


def normalize_privacy_laws_adhered_to(value):
    return unique_values(value, mapper=lambda item: PRIVACY_LAW_LEGACY_MAP.get(item, item))


def normalize_security_privacy_standards(value):
    return unique_values(value)


def normalize_sector_specific_contextual_laws(value):
    return unique_values(value, mapper=lambda item: "FERPA" if item == "FERP" else item)


def normalize_cross_border_data_transfer_mechanisms(value):
    return unique_values(
        value,
        mapper=lambda item: "EU-US Data Privacy Framework (DPF)"
        if item == "EU-US Data Privacy Framework"
        else item,
    )


def normalize_us_specific_laws(value):
    return unique_values(value)


PRIVACY_FIELD_NORMALIZERS = {
    "data_types_stored": normalize_data_types_stored,
    "data_storage_location": normalize_data_storage_locations,
    "privacy_laws_adhered_to": normalize_privacy_laws_adhered_to,
    "security_privacy_standards": normalize_security_privacy_standards,
    "sector_specific_contextual_laws": normalize_sector_specific_contextual_laws,
    "cross_border_data_transfer_mechanisms": normalize_cross_border_data_transfer_mechanisms,
    "us_specific_laws": normalize_us_specific_laws,
}

PDF_TEXT_REPLACEMENTS = str.maketrans(
    {
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": "-",
        "\u2212": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2022": "-",
        "\u00a0": " ",
    }
)


def normalize_privacy_fields(record):
    for field, normalizer in PRIVACY_FIELD_NORMALIZERS.items():
        if field in record:
            record[field] = normalizer(record.get(field, ""))
    return record


def format_assessment_value(field, value, record=None):
    if field in CHECKBOX_FIELDS:
        return "Yes" if value else "No"

    if field in MULTI_SELECT_FIELDS:
        values = get_selected_values(value)
        return ", ".join(values) if values else "Not provided"

    reminder_labels = {
        "6_months": "Every 6 months",
        "1_year": "Every 1 year",
        "2_years": "Every 2 years",
    }
    if field == "audit_reminder_frequency":
        return reminder_labels.get(value, value or "Not provided")

    if field == "license_cost":
        if (record or {}).get("free_software") or (record or {}).get("license_type") == "Free":
            return "Free"
        amount = str(value).strip()
        if not amount:
            return "Not provided"
        currency = str((record or {}).get("currency_type", "")).strip()
        return f"{currency} {amount}".strip() if currency else amount

    return str(value).strip() if str(value).strip() else "Not provided"


def clean_pdf_text(value):
    return str(value).translate(PDF_TEXT_REPLACEMENTS)


def pdf_paragraph(value, style, preserve_line_breaks=False):
    text = escape(clean_pdf_text(value))
    if preserve_line_breaks:
        text = text.replace("\n", "<br/>")
    return Paragraph(text, style)


def build_assessment_pdf(record, cve_data=None):
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"{record.get('software_name', 'Software')} Audit Report",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#016936"),
        alignment=TA_LEFT,
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#2a4238"),
        spaceAfter=12,
    )
    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.white,
        backColor=colors.HexColor("#016936"),
        borderPadding=(6, 10, 6),
        spaceBefore=10,
        spaceAfter=8,
    )
    label_style = ParagraphStyle(
        "FieldLabel",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#2a4238"),
    )
    value_style = ParagraphStyle(
        "FieldValue",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#2a4238"),
    )

    story = []
    if PDF_LOGO_PATH.exists():
        logo = PlatypusImage(str(PDF_LOGO_PATH))
        max_width = 24 * mm
        max_height = 14 * mm
        scale = min(max_width / logo.imageWidth, max_height / logo.imageHeight, 1)
        logo.drawWidth = logo.imageWidth * scale
        logo.drawHeight = logo.imageHeight * scale
        story.append(logo)
        story.append(Spacer(1, 5))
    story.append(Paragraph("Software Security Audit Report", title_style))
    story.append(
        Paragraph(
            "A structured export of the saved software assessment, including governance, security, deployment, and audit schedule details.",
            subtitle_style,
        )
    )

    summary_rows = [
        [
            Paragraph("<b>Software</b>", label_style),
            pdf_paragraph(format_assessment_value("software_name", record.get("software_name", ""), record), value_style),
            Paragraph("<b>Vendor</b>", label_style),
            pdf_paragraph(format_assessment_value("vendor_name", record.get("vendor_name", ""), record), value_style),
        ],
        [
            Paragraph("<b>Risk Level</b>", label_style),
            Paragraph(
                escape(clean_pdf_text(format_assessment_value("risk_level", record.get("risk_level", ""), record))),
                value_style,
            ),
            Paragraph("<b>Next Audit Date</b>", label_style),
            pdf_paragraph(format_assessment_value("next_audit_date", record.get("next_audit_date", ""), record), value_style),
        ],
        [
            Paragraph("<b>Assessment Date</b>", label_style),
            pdf_paragraph(format_assessment_value("assessment_date", record.get("assessment_date", ""), record), value_style),
            Paragraph("<b>Report Generated</b>", label_style),
            Paragraph(date.today().isoformat(), value_style),
        ],
    ]
    summary_table = Table(summary_rows, colWidths=[34 * mm, 48 * mm, 34 * mm, 48 * mm], hAlign="LEFT")
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ebfdf2")),
                ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 8))

    fired_alerts = set()
    alert_visibility = get_alert_pdf_visibility()
    for section_title, fields in PDF_SECTION_FIELDS:
        table_rows = []
        for field in fields:
            if field in PDF_HIDDEN_FIELDS:
                continue
            if field == "license_renewal_date" and record.get("license_type") == "Perpetual":
                continue
            if field == "allows_acceptance_on_behalf_of_entity" and record.get("age_restrictions", "") in ("", "None"):
                continue
            if field == "license_cost" and (record.get("free_software") or record.get("license_type") == "Free" or not str(record.get("license_cost", "")).strip()):
                continue
            if field in ("product_updates", "security_updates") and record.get("software_type") == "SaaS":
                continue
            label = PDF_FIELD_LABELS.get(field, field.replace("_", " ").title())
            value = format_assessment_value(field, record.get(field, ""), record)
            if value == "Not provided":
                continue
            table_rows.append(
                [
                    pdf_paragraph(label, label_style),
                    pdf_paragraph(value, value_style, preserve_line_breaks=True),
                ]
            )

        if not table_rows:
            continue

        story.append(Paragraph(section_title, section_style))
        section_table = Table(table_rows, colWidths=[58 * mm, 116 * mm], hAlign="LEFT")
        section_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                    ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#D1D5DB")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.45, colors.HexColor("#E5E7EB")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ebfdf2")),
                ]
            )
        )
        story.append(section_table)
        story.append(Spacer(1, 8))

        if section_title == "Software Information":
            category_name = clean_pdf_text(record.get("category", "")).strip()
            genuine_need = clean_pdf_text(record.get("genuine_need", "")).strip()
            if category_name:
                story.append(Paragraph("Category and Genuine Need", section_style))
                cat_rows = [
                    [
                        pdf_paragraph("Category", label_style),
                        pdf_paragraph(category_name, value_style),
                    ],
                    [
                        pdf_paragraph("Genuine Need", label_style),
                        pdf_paragraph(genuine_need or "Not recorded", value_style, preserve_line_breaks=True),
                    ],
                ]
                cat_table = Table(cat_rows, colWidths=[58 * mm, 116 * mm], hAlign="LEFT")
                cat_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                            ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#D1D5DB")),
                            ("INNERGRID", (0, 0), (-1, -1), 0.45, colors.HexColor("#E5E7EB")),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("LEFTPADDING", (0, 0), (-1, -1), 8),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                            ("TOPPADDING", (0, 0), (-1, -1), 7),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ebfdf2")),
                        ]
                    )
                )
                story.append(cat_table)
                story.append(Spacer(1, 8))
            else:
                no_cat_heading_style = ParagraphStyle(
                    "NoCategoryHeading",
                    parent=styles["BodyText"],
                    fontSize=9,
                    leading=13,
                    textColor=colors.HexColor("#92400E"),
                    fontName="Helvetica-Bold",
                    spaceAfter=2,
                )
                no_cat_body_style = ParagraphStyle(
                    "NoCategoryBody",
                    parent=styles["BodyText"],
                    fontSize=8.5,
                    leading=12,
                    textColor=colors.HexColor("#92400E"),
                )
                no_cat_cell = [
                    Paragraph("No genuine need recorded for this software.", no_cat_heading_style),
                    Paragraph(
                        "This software has not been assigned to a category. A genuine need statement "
                        "is required before this software can be approved for deployment.",
                        no_cat_body_style,
                    ),
                ]
                no_cat_table = Table([[no_cat_cell]], colWidths=[174 * mm], hAlign="LEFT")
                no_cat_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                            ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                            ("LEFTPADDING", (0, 0), (-1, -1), 10),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                            ("TOPPADDING", (0, 0), (-1, -1), 8),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ]
                    )
                )
                fired_alerts.add("no_category")
                story.append(no_cat_table)
                story.append(Spacer(1, 10))

    if (
        record.get("student_intended_use") == "Yes"
        and record.get("age_restrictions", "") not in ("", "None")
        and record.get("allows_acceptance_on_behalf_of_entity") != "Yes"
    ):
        alert_heading_style = ParagraphStyle(
            "AlertHeading",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#92400E"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        )
        alert_body_style = ParagraphStyle(
            "AlertBody",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#92400E"),
        )
        age_restriction_value = record.get("age_restrictions", "")
        alert_cell = [
            Paragraph("Acceptance terms require individual consent.", alert_heading_style),
            Paragraph(
                f"This software is intended for student use and has age restrictions ({age_restriction_value}), "
                "but the vendor's terms do not permit the college to accept on behalf of students. "
                "Individual student or parental consent may be required before deployment.",
                alert_body_style,
            ),
        ]
        alert_table = Table([[alert_cell]], colWidths=[174 * mm], hAlign="LEFT")
        alert_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        fired_alerts.add("age_restriction")
        story.append(alert_table)
        story.append(Spacer(1, 10))

    vendor_name = record.get("vendor_name", "")
    vendor_map = build_vendor_data_storage_map(vendor_name) if vendor_name else {"high_risk_locations": []}
    vendor_high_risk_locations = vendor_map["high_risk_locations"]
    if vendor_high_risk_locations:
        vendor_alert_heading_style = ParagraphStyle(
            "VendorAlertHeading",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#92400E"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        )
        vendor_alert_body_style = ParagraphStyle(
            "VendorAlertBody",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#92400E"),
        )
        if len(vendor_high_risk_locations) == 1:
            locations_text = f"<b>{vendor_high_risk_locations[0]}</b>, which is classified as high risk"
        else:
            locations_text = ", ".join(f"<b>{loc}</b>" for loc in vendor_high_risk_locations) + ", which are classified as high risk"
        vendor_alert_cell = [
            Paragraph("High-risk data storage locations detected.", vendor_alert_heading_style),
            Paragraph(
                f"The latest audit for {vendor_name} lists data stored in {locations_text}. "
                "Review data transfer mechanisms and ensure appropriate safeguards are in place.",
                vendor_alert_body_style,
            ),
        ]
        vendor_alert_table = Table([[vendor_alert_cell]], colWidths=[174 * mm], hAlign="LEFT")
        vendor_alert_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        fired_alerts.add("high_risk_locations")
        story.append(vendor_alert_table)
        story.append(Spacer(1, 10))

    if record.get("vendor_name") and record.get("no_vendor_terms_conditions"):
        tc_alert_heading_style = ParagraphStyle(
            "TcAlertHeading",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#92400E"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        )
        tc_alert_body_style = ParagraphStyle(
            "TcAlertBody",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#92400E"),
        )
        tc_alert_cell = [
            Paragraph("No vendor terms and conditions available.", tc_alert_heading_style),
            Paragraph(
                f"{vendor_name or 'This vendor'} does not have terms and conditions available. "
                "Confirm whether terms and conditions exist before deployment.",
                tc_alert_body_style,
            ),
        ]
        tc_alert_table = Table([[tc_alert_cell]], colWidths=[174 * mm], hAlign="LEFT")
        tc_alert_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        fired_alerts.add("no_tc")
        story.append(tc_alert_table)
        story.append(Spacer(1, 10))

    if record.get("vendor_name") and not record.get("online_support", ""):
        support_alert_heading_style = ParagraphStyle(
            "SupportAlertHeading",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#92400E"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        )
        support_alert_body_style = ParagraphStyle(
            "SupportAlertBody",
            parent=styles["BodyText"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#92400E"),
        )
        support_alert_cell = [
            Paragraph("No online support link on record.", support_alert_heading_style),
            Paragraph(
                f"{vendor_name} does not have an online support link on record. "
                "Consider whether this affects the supportability of this software.",
                support_alert_body_style,
            ),
        ]
        support_alert_table = Table([[support_alert_cell]], colWidths=[174 * mm], hAlign="LEFT")
        support_alert_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        fired_alerts.add("no_support")
        story.append(support_alert_table)
        story.append(Spacer(1, 10))

    if OTHER_DATA_STORAGE_LOCATION in vendor_map.get("locations", []):
        unspecified_heading_style = ParagraphStyle(
            "UnspecifiedHeading",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#92400E"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        )
        unspecified_body_style = ParagraphStyle(
            "UnspecifiedBody",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#92400E"),
        )
        unspecified_cell = [
            Paragraph("Unspecified data hosting locations.", unspecified_heading_style),
            Paragraph(
                f"The latest audit for {vendor_name} lists data hosted in unspecified overseas locations. "
                "This is common where vendors utilise distributed cloud infrastructure across multiple data centres, "
                "such as Amazon Web Services (AWS) or Microsoft Azure. Confirm a Data Processing Agreement (DPA) is "
                "in place to govern overseas data transfers and bridge obligations under the Australian Privacy Principles (APP).",
                unspecified_body_style,
            ),
        ]
        unspecified_table = Table([[unspecified_cell]], colWidths=[174 * mm], hAlign="LEFT")
        unspecified_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        fired_alerts.add("unspecified_locations")
        story.append(unspecified_table)
        story.append(Spacer(1, 10))

    if vendor_map.get("no_privacy_policy"):
        no_privacy_heading_style = ParagraphStyle(
            "NoPrivacyHeading",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#92400E"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        )
        no_privacy_body_style = ParagraphStyle(
            "NoPrivacyBody",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#92400E"),
        )
        no_privacy_cell = [
            Paragraph("No vendor privacy policy available.", no_privacy_heading_style),
            Paragraph(
                f"{vendor_name} does not have a privacy policy on record. "
                "Confirm whether a privacy policy exists before deployment.",
                no_privacy_body_style,
            ),
        ]
        no_privacy_table = Table([[no_privacy_cell]], colWidths=[174 * mm], hAlign="LEFT")
        no_privacy_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        fired_alerts.add("no_privacy_policy")
        story.append(no_privacy_table)
        story.append(Spacer(1, 10))

    if vendor_map.get("dpa_status") == "Not Obtained":
        dpa_heading_style = ParagraphStyle(
            "DpaHeading",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#92400E"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        )
        dpa_body_style = ParagraphStyle(
            "DpaBody",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#92400E"),
        )
        dpa_cell = [
            Paragraph("Data Processing Agreement not obtained.", dpa_heading_style),
            Paragraph(
                f"{vendor_name or 'This vendor'} stores data outside the home country but no Data Processing "
                "Agreement has been recorded. Update the vendor audit once the DPA is in place.",
                dpa_body_style,
            ),
        ]
        dpa_table = Table([[dpa_cell]], colWidths=[174 * mm], hAlign="LEFT")
        dpa_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        fired_alerts.add("dpa_not_obtained")
        story.append(dpa_table)
        story.append(Spacer(1, 10))

    if vendor_map.get("dpa_status") == "Obtained":
        app_notice_heading_style = ParagraphStyle(
            "AppNoticeHeading",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#92400E"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        )
        app_notice_body_style = ParagraphStyle(
            "AppNoticeBody",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#92400E"),
        )
        app_notice_cell = [
            Paragraph("APP Collection Notice reminder.", app_notice_heading_style),
            Paragraph(
                "A current Collection Notice to parents/guardians is required to meet Australian Privacy Principles (APP) "
                "obligations. The Collection Notice authorises the college to rely on a Data Processing Agreement (DPA) to "
                "govern overseas data transfers on behalf of students and families. Software deployments involving overseas "
                "data transfer should be reflected in the college's Collection Notice, issued as part of enrolment or other "
                "standard communications.",
                app_notice_body_style,
            ),
        ]
        app_notice_table = Table([[app_notice_cell]], colWidths=[174 * mm], hAlign="LEFT")
        app_notice_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        fired_alerts.add("app_collection_notice")
        story.append(app_notice_table)
        story.append(Spacer(1, 10))

    if record.get("is_assessment") and not record.get("tested"):
        not_tested_heading_style = ParagraphStyle(
            "NotTestedHeading",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#92400E"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        )
        not_tested_body_style = ParagraphStyle(
            "NotTestedBody",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#92400E"),
        )
        not_tested_cell = [
            Paragraph("Software has not been tested.", not_tested_heading_style),
            Paragraph(
                "This software has not been marked as tested. Confirm that appropriate "
                "testing has been completed before deployment.",
                not_tested_body_style,
            ),
        ]
        not_tested_table = Table([[not_tested_cell]], colWidths=[174 * mm], hAlign="LEFT")
        not_tested_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        fired_alerts.add("not_tested")
        story.append(not_tested_table)
        story.append(Spacer(1, 10))

    if record.get("is_assessment") and not record.get("st4s_compliant", ""):
        st4s_heading_style = ParagraphStyle(
            "ST4SHeading",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#92400E"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        )
        st4s_body_style = ParagraphStyle(
            "ST4SBody",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#92400E"),
        )
        st4s_cell = [
            Paragraph("ST4S compliance not assessed.", st4s_heading_style),
            Paragraph(
                "This software has not been assessed against the ST4S framework. "
                "An ST4S compliance status should be recorded before this report is finalised.",
                st4s_body_style,
            ),
        ]
        st4s_table = Table([[st4s_cell]], colWidths=[174 * mm], hAlign="LEFT")
        st4s_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        fired_alerts.add("st4s_not_assessed")
        story.append(st4s_table)
        story.append(Spacer(1, 10))

    if record.get("is_assessment") and not record.get("essential_eight_compliant", ""):
        e8_heading_style = ParagraphStyle(
            "E8Heading",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#92400E"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        )
        e8_body_style = ParagraphStyle(
            "E8Body",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#92400E"),
        )
        e8_cell = [
            Paragraph("Essential 8 compliance not assessed.", e8_heading_style),
            Paragraph(
                "This software has not been assessed against the Australian Cyber Security Centre's "
                "Essential Eight mitigation strategies. An Essential 8 compliance status should be "
                "recorded before this report is finalised.",
                e8_body_style,
            ),
        ]
        e8_table = Table([[e8_cell]], colWidths=[174 * mm], hAlign="LEFT")
        e8_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        fired_alerts.add("essential_eight_not_assessed")
        story.append(e8_table)
        story.append(Spacer(1, 10))

    if record.get("is_assessment") and not record.get("product_updates") and record.get("software_type") != "SaaS":
        no_prod_heading_style = ParagraphStyle(
            "NoProdUpdatesHeading",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#92400E"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        )
        no_prod_body_style = ParagraphStyle(
            "NoProdUpdatesBody",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#92400E"),
        )
        no_prod_cell = [
            Paragraph("No product updates available.", no_prod_heading_style),
            Paragraph(
                "This software does not offer product updates. "
                "Review whether continued use is appropriate without access to new features or bug fixes.",
                no_prod_body_style,
            ),
        ]
        no_prod_table = Table([[no_prod_cell]], colWidths=[174 * mm], hAlign="LEFT")
        no_prod_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        fired_alerts.add("no_product_updates")
        story.append(no_prod_table)
        story.append(Spacer(1, 10))

    if record.get("is_assessment") and not record.get("security_updates") and record.get("software_type") != "SaaS":
        no_sec_heading_style = ParagraphStyle(
            "NoSecUpdatesHeading",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#92400E"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        )
        no_sec_body_style = ParagraphStyle(
            "NoSecUpdatesBody",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#92400E"),
        )
        no_sec_cell = [
            Paragraph("No security updates available.", no_sec_heading_style),
            Paragraph(
                "This software does not offer security updates. "
                "Review whether this poses an ongoing security risk before deployment or continued use.",
                no_sec_body_style,
            ),
        ]
        no_sec_table = Table([[no_sec_cell]], colWidths=[174 * mm], hAlign="LEFT")
        no_sec_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        fired_alerts.add("no_security_updates")
        story.append(no_sec_table)
        story.append(Spacer(1, 10))

    if record.get("supports_m365_sso") in ("No SSO", "Third Party IdP"):
        sso_alert_heading_style = ParagraphStyle(
            "SsoAlertHeading",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#92400E"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        )
        sso_alert_body_style = ParagraphStyle(
            "SsoAlertBody",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#92400E"),
        )
        sso_alert_cell = [
            Paragraph("SSO integration not available via Microsoft Entra.", sso_alert_heading_style),
            Paragraph(
                "This software does not integrate with the college’s Entra (Microsoft 365) identity provider. "
                "Local or third-party accounts will need to be managed outside of Entra, increasing administrative "
                "overhead and security risk. The IT Director should review access management implications before "
                "approving deployment.",
                sso_alert_body_style,
            ),
        ]
        sso_alert_table = Table([[sso_alert_cell]], colWidths=[174 * mm], hAlign="LEFT")
        sso_alert_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        fired_alerts.add("sso")
        story.append(sso_alert_table)
        story.append(Spacer(1, 10))

    if cve_data and cve_data.get("cves"):
        _severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        highest_severity = max(
            (c.get("severity", "") for c in cve_data["cves"]),
            key=lambda s: _severity_rank.get(s, 0),
            default="",
        )
        cve_count = cve_data["total"]
        cve_ids = ", ".join(c["id"] for c in cve_data["cves"][:5])
        if cve_data["total"] > 5:
            cve_ids += f" and {cve_data['total'] - 5} more"
        cve_alert_heading_style = ParagraphStyle(
            "CveAlertHeading",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#92400E"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        )
        cve_alert_body_style = ParagraphStyle(
            "CveAlertBody",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#92400E"),
        )
        cve_alert_cell = [
            Paragraph("Known vulnerabilities detected.", cve_alert_heading_style),
            Paragraph(
                f"{cve_count} active CVE(s) matched for {escape(clean_pdf_text(record.get('software_name', '')))} "
                f"in the National Vulnerability Database (NVD). "
                f"Highest severity: {escape(clean_pdf_text(highest_severity))}. "
                f"CVEs include: {escape(clean_pdf_text(cve_ids))}. "
                "Results are keyword-matched and may include related products — verify each CVE applies to this software.",
                cve_alert_body_style,
            ),
        ]
        cve_alert_table = Table([[cve_alert_cell]], colWidths=[174 * mm], hAlign="LEFT")
        cve_alert_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        fired_alerts.add("cve")
        story.append(cve_alert_table)
        story.append(Spacer(1, 10))

    it_recommendation = record.get("it_recommendation", "").strip()
    it_rec_section_style = ParagraphStyle(
        "ItRecSectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.white,
        backColor=colors.HexColor("#016936"),
        borderPadding=(6, 10, 6),
        spaceBefore=10,
        spaceAfter=8,
    )
    it_rec_text_style = ParagraphStyle(
        "ItRecText",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#2a4238"),
    )
    story.append(Paragraph("IT Recommendation", it_rec_section_style))
    if it_recommendation:
        it_rec_table = Table(
            [[pdf_paragraph(it_recommendation, it_rec_text_style)]],
            colWidths=[174 * mm],
            hAlign="LEFT",
        )
        it_rec_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0FDF4")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(it_rec_table)
    else:
        no_rec_heading_style = ParagraphStyle(
            "NoItRecHeading",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#92400E"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        )
        no_rec_body_style = ParagraphStyle(
            "NoItRecBody",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#92400E"),
        )
        no_rec_cell = [
            Paragraph("No IT recommendation recorded.", no_rec_heading_style),
            Paragraph(
                "An IT recommendation has not been provided for this software. "
                "IT should record a recommendation before this report is signed.",
                no_rec_body_style,
            ),
        ]
        no_rec_table = Table([[no_rec_cell]], colWidths=[174 * mm], hAlign="LEFT")
        no_rec_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D1D5DB")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        fired_alerts.add("no_it_recommendation")
        story.append(no_rec_table)
    story.append(Spacer(1, 10))

    signatory_config = get_signatory_alerts()
    signature_roles = [
        role for role in SIGNATORY_ROLES
        if set(signatory_config.get(role, [])) & fired_alerts
    ]

    if signature_roles:
        story.append(Paragraph("Signatures", section_style))
        sig_field_label_style = ParagraphStyle(
            "SigFieldLabel",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#6B7280"),
        )
        signature_rows = [
            [
                pdf_paragraph(role, label_style),
                Paragraph("Signature", sig_field_label_style),
                Paragraph("", value_style),
                Paragraph("Date", sig_field_label_style),
                Paragraph("", value_style),
            ]
            for role in signature_roles
        ]
        sig_style_commands = [
            ("BACKGROUND", (0, 0), (-1, -1), colors.white),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ebfdf2")),
            ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#D1D5DB")),
            ("LINEAFTER", (0, 0), (0, -1), 0.45, colors.HexColor("#E5E7EB")),
            ("VALIGN", (0, 0), (0, -1), "MIDDLE"),
            ("VALIGN", (1, 0), (-1, -1), "BOTTOM"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 16),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (2, 0), (2, -1), 16),
            ("LEFTPADDING", (3, 0), (3, -1), 4),
        ]
        for row_idx in range(len(signature_rows)):
            sig_style_commands.append(("LINEBELOW", (2, row_idx), (2, row_idx), 0.75, colors.HexColor("#374151")))
            sig_style_commands.append(("LINEBELOW", (4, row_idx), (4, row_idx), 0.75, colors.HexColor("#374151")))
        signature_table = Table(
            signature_rows,
            colWidths=[40 * mm, 22 * mm, 60 * mm, 14 * mm, 38 * mm],
            hAlign="LEFT",
        )
        signature_table.setStyle(TableStyle(sig_style_commands))
        story.append(signature_table)
        story.append(Spacer(1, 8))

    # --- Risk Matrix page ---
    story.append(PageBreak())
    story.append(Paragraph("Alert Risk Matrix", section_style))
    story.append(Spacer(1, 4))

    alert_risk_levels = get_alert_risk_levels()
    risk_order = {level: i for i, level in enumerate(RISK_CATEGORY_OPTIONS)}

    matrix_header_style = ParagraphStyle(
        "MatrixHeader",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=colors.white,
    )
    matrix_label_style = ParagraphStyle(
        "MatrixLabel",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#111827"),
    )
    matrix_risk_style = ParagraphStyle(
        "MatrixRisk",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#111827"),
    )
    matrix_status_style = ParagraphStyle(
        "MatrixStatus",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
    )

    risk_bg = {
        "Low": colors.HexColor("#dcfce7"),
        "Moderate": colors.HexColor("#fef9c3"),
        "High": colors.HexColor("#ffedd5"),
        "Very High": colors.HexColor("#fee2e2"),
    }
    risk_badge = {
        "Low": colors.HexColor("#22c55e"),
        "Moderate": colors.HexColor("#ca8a04"),
        "High": colors.HexColor("#f97316"),
        "Very High": colors.HexColor("#dc2626"),
    }

    def sorted_alert_keys():
        def sort_key(k):
            level = alert_risk_levels.get(k, "")
            return (risk_order.get(level, len(RISK_CATEGORY_OPTIONS)), PDF_ALERT_LABELS[k])
        visible_keys = [k for k in PDF_ALERT_LABELS if alert_visibility.get(k, True)]
        return sorted(visible_keys, key=sort_key, reverse=False)

    matrix_rows = [[
        Paragraph("Alert", matrix_header_style),
        Paragraph("Risk Level", matrix_header_style),
        Paragraph("Status", matrix_header_style),
    ]]
    matrix_style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#016936")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#D1D5DB")),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E5E7EB")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]

    for row_idx, key in enumerate(sorted_alert_keys(), start=1):
        label = PDF_ALERT_LABELS[key]
        level = alert_risk_levels.get(key, "")
        fired = key in fired_alerts

        bg = risk_bg.get(level, colors.white)
        badge_color = risk_badge.get(level, colors.HexColor("#6b7280"))
        risk_text_color = badge_color

        status_text = "Triggered" if fired else "Not triggered"
        status_color = colors.HexColor("#dc2626") if fired else colors.HexColor("#6b7280")

        risk_para_style = ParagraphStyle(
            f"MRisk_{row_idx}",
            parent=matrix_risk_style,
            textColor=risk_text_color,
        )
        status_para_style = ParagraphStyle(
            f"MStatus_{row_idx}",
            parent=matrix_status_style,
            textColor=status_color,
        )

        matrix_rows.append([
            Paragraph(label, matrix_label_style),
            Paragraph(level or "Not assigned", risk_para_style),
            Paragraph(status_text, status_para_style),
        ])
        if level:
            matrix_style_cmds.append(("BACKGROUND", (1, row_idx), (1, row_idx), bg))
        if fired:
            matrix_style_cmds.append(("BACKGROUND", (2, row_idx), (2, row_idx), colors.HexColor("#fef2f2")))

    matrix_table = Table(matrix_rows, colWidths=[110 * mm, 34 * mm, 30 * mm], hAlign="LEFT")
    matrix_table.setStyle(TableStyle(matrix_style_cmds))
    story.append(matrix_table)

    doc.build(story)
    buffer.seek(0)
    result = buffer

    vendor_name = record.get("vendor_name", "")
    if vendor_name:
        vendor = get_vendor_record_or_none(vendor_name)
        if vendor:
            pdf_filename = vendor.get("privacy_policy_pdf_filename", "")
            if pdf_filename:
                pdf_path = UPLOADS_DIR / pdf_filename
                if pdf_path.exists():
                    try:
                        writer = PdfWriter()
                        for page in PdfReader(result).pages:
                            writer.add_page(page)
                        for page in PdfReader(str(pdf_path)).pages:
                            writer.add_page(page)
                        merged = BytesIO()
                        writer.write(merged)
                        merged.seek(0)
                        result = merged
                    except Exception:
                        result.seek(0)

            tc_pdf_filename = vendor.get("vendor_tc_pdf_filename", "")
            if tc_pdf_filename:
                tc_pdf_path = UPLOADS_DIR / tc_pdf_filename
                if tc_pdf_path.exists():
                    try:
                        writer = PdfWriter()
                        for page in PdfReader(result).pages:
                            writer.add_page(page)
                        for page in PdfReader(str(tc_pdf_path)).pages:
                            writer.add_page(page)
                        merged = BytesIO()
                        writer.write(merged)
                        merged.seek(0)
                        result = merged
                    except Exception:
                        result.seek(0)

    software_name = record.get("software_name", "")
    if software_name:
        software_item = get_software_item_by_name(software_name)
        if software_item:
            eula_filename = software_item.get("eula_pdf_filename", "")
            if eula_filename:
                eula_path = UPLOADS_DIR / eula_filename
                if eula_path.exists():
                    try:
                        writer = PdfWriter()
                        for page in PdfReader(result).pages:
                            writer.add_page(page)
                        for page in PdfReader(str(eula_path)).pages:
                            writer.add_page(page)
                        merged = BytesIO()
                        writer.write(merged)
                        merged.seek(0)
                        result = merged
                    except Exception:
                        result.seek(0)

    return result


def create_assessment(record_id, **values):
    record = blank_assessment()
    record.update(values)
    record["id"] = record_id
    record["is_assessment"] = True
    record["submission_status"] = "submitted"
    return enrich_assessment(record)


DEFAULT_APP_SETTINGS = {
    "reminder_email": "it-audits@example.com",
    "home_country": "Australia",
    "country_risk_assignments": "{}",
    "dark_mode": "false",
    "category_required": "true",
    "signatory_alerts": json.dumps({
        "IT Director": ["sso", "cve", "no_tc", "no_support", "not_tested", "no_product_updates", "no_security_updates", "high_risk_locations", "no_category"],
        "Privacy Officer": ["dpa_not_obtained", "app_collection_notice", "high_risk_locations", "no_privacy_policy", "unspecified_locations"],
        "College Principal": ["age_restriction", "no_category"],
    }),
    "alert_risk_levels": json.dumps({
        "no_category": "Low",
        "age_restriction": "High",
        "high_risk_locations": "High",
        "no_tc": "Moderate",
        "no_support": "Low",
        "unspecified_locations": "Moderate",
        "no_privacy_policy": "Moderate",
        "dpa_not_obtained": "High",
        "app_collection_notice": "Low",
        "not_tested": "Moderate",
        "st4s_not_assessed": "Moderate",
        "essential_eight_not_assessed": "Moderate",
        "no_product_updates": "Moderate",
        "no_security_updates": "Moderate",
        "sso": "Low",
        "cve": "Very High",
        "no_it_recommendation": "Moderate",
    }),
    "alert_pdf_visibility": json.dumps({}),
}
SOFTWARE_ITEMS = []
SOFTWARE_ASSESSMENT_RECORDS = []
SOFTWARE_RECORDS = []
NEXT_SOFTWARE_ID = 1
NEXT_ASSESSMENT_ID = 1
VENDOR_RECORDS = []
VENDOR_ASSESSMENT_RECORDS = []
NEXT_VENDOR_ASSESSMENT_ID = 1
NEXT_CATEGORY_ID = 1
CATEGORIES: list = []
APP_SETTINGS = dict(DEFAULT_APP_SETTINGS)
RISK_CATEGORY_OPTIONS = (
    "Low",
    "Moderate",
    "High",
    "Very High",
)
RISK_LEVEL_LEGACY_MAP = {
    "Medium": "Moderate",
    "Critical": "Very High",
}


def normalize_risk_level(value):
    cleaned = str(value or "").strip()
    return RISK_LEVEL_LEGACY_MAP.get(cleaned, cleaned)
RISK_CATEGORY_MAP_COLORS = {
    "Low": "#22c55e",
    "Moderate": "#facc15",
    "High": "#f97316",
    "Very High": "#dc2626",
}
DEFAULT_MAP_RISK_COLOR = "#2563eb"
SIGNATORY_ROLES = ("IT Director", "Privacy Officer", "College Principal")
PDF_ALERT_LABELS = {
    "no_category": "No genuine need recorded",
    "age_restriction": "Acceptance terms require individual consent",
    "high_risk_locations": "High-risk data storage locations",
    "no_tc": "No vendor terms and conditions",
    "no_support": "No online support link",
    "unspecified_locations": "Unspecified data hosting locations",
    "no_privacy_policy": "No vendor privacy policy",
    "dpa_not_obtained": "Data Processing Agreement not obtained",
    "app_collection_notice": "APP Collection Notice reminder",
    "not_tested": "Software not tested",
    "st4s_not_assessed": "ST4S not assessed",
    "essential_eight_not_assessed": "Essential 8 not assessed",
    "no_product_updates": "No product updates",
    "no_security_updates": "No security updates",
    "sso": "SSO not available via Microsoft Entra",
    "cve": "Known vulnerabilities (CVE)",
    "no_it_recommendation": "No IT recommendation recorded",
}


def get_db_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=MEMORY")
    connection.execute("PRAGMA synchronous=NORMAL")
    return connection


def init_db():
    DB_DIRECTORY.mkdir(parents=True, exist_ok=True)
    with get_db_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessments (
                id INTEGER PRIMARY KEY,
                data TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS software (
                id INTEGER PRIMARY KEY,
                vendor_name TEXT NOT NULL,
                software_name TEXT NOT NULL,
                data TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS software_assessments (
                id INTEGER PRIMARY KEY,
                software_id INTEGER,
                software_name TEXT NOT NULL,
                data TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS vendors (
                name TEXT PRIMARY KEY,
                data TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS vendor_entities (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                country_of_origin TEXT NOT NULL DEFAULT '',
                data TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS vendor_assessments (
                id INTEGER PRIMARY KEY,
                vendor_name TEXT NOT NULL,
                data TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS data_storage_countries (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS data_storage_country_groups (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS data_storage_country_group_memberships (
                group_id INTEGER NOT NULL,
                country_id INTEGER NOT NULL,
                PRIMARY KEY (group_id, country_id),
                FOREIGN KEY (group_id) REFERENCES data_storage_country_groups (id),
                FOREIGN KEY (country_id) REFERENCES data_storage_countries (id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS vendor_data_storage_countries (
                vendor_id INTEGER NOT NULL,
                country_id INTEGER NOT NULL,
                PRIMARY KEY (vendor_id, country_id),
                FOREIGN KEY (vendor_id) REFERENCES vendor_entities (id),
                FOREIGN KEY (country_id) REFERENCES data_storage_countries (id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                genuine_need TEXT NOT NULL DEFAULT ''
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS country_risk_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                country TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                comment TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )


def sync_data_storage_reference_tables():
    with get_db_connection() as connection:
        connection.executemany(
            "INSERT OR IGNORE INTO data_storage_countries (name) VALUES (?)",
            [(country,) for country in COUNTRY_OPTIONS],
        )
        connection.executemany(
            "INSERT OR IGNORE INTO data_storage_country_groups (name) VALUES (?)",
            [(group_name,) for group_name, _ in DATA_STORAGE_COUNTRY_GROUPS],
        )

        country_id_by_name = {
            row["name"]: row["id"]
            for row in connection.execute("SELECT id, name FROM data_storage_countries").fetchall()
        }
        group_id_by_name = {
            row["name"]: row["id"]
            for row in connection.execute("SELECT id, name FROM data_storage_country_groups").fetchall()
        }

        connection.execute("DELETE FROM data_storage_country_group_memberships")
        membership_rows = []
        for group_name, country_names in DATA_STORAGE_COUNTRY_GROUPS:
            group_id = group_id_by_name.get(group_name)
            if group_id is None:
                continue
            for country_name in country_names:
                country_id = country_id_by_name.get(country_name)
                if country_id is not None:
                    membership_rows.append((group_id, country_id))
        connection.executemany(
            """
            INSERT INTO data_storage_country_group_memberships (group_id, country_id)
            VALUES (?, ?)
            """,
            membership_rows,
        )


def build_vendor_catalog_for_sync():
    vendors_by_name = {}

    for vendor in globals().get("VENDOR_RECORDS", []):
        vendor_name = vendor.get("vendor_name", "").strip()
        if not vendor_name:
            continue
        vendors_by_name[normalized_name(vendor_name)] = {
            field: vendor.get(field, "")
            for field in VENDOR_PROFILE_FIELDS
        }
        vendors_by_name[normalized_name(vendor_name)]["vendor_name"] = vendor_name

    for software in globals().get("SOFTWARE_ITEMS", []):
        vendor_name = software.get("vendor_name", "").strip()
        if not vendor_name:
            continue
        vendor_key = normalized_name(vendor_name)
        vendor_record = vendors_by_name.setdefault(
            vendor_key,
            {field: "" for field in VENDOR_PROFILE_FIELDS},
        )
        vendor_record["vendor_name"] = vendor_record.get("vendor_name") or vendor_name
        if not vendor_record.get("vendor_country"):
            vendor_record["vendor_country"] = software.get("vendor_country", "").strip()

    return sorted(
        vendors_by_name.values(),
        key=lambda vendor: normalized_name(vendor.get("vendor_name", "")),
    )


def sync_vendor_entity_tables():
    vendor_catalog = build_vendor_catalog_for_sync()
    vendor_names = [vendor.get("vendor_name", "").strip() for vendor in vendor_catalog if vendor.get("vendor_name", "").strip()]
    latest_submitted_assessments = {}
    for assessment in globals().get("VENDOR_ASSESSMENT_RECORDS", []):
        if not is_submitted_vendor_assessment(assessment):
            continue
        vendor_key = normalized_name(assessment.get("vendor_name", ""))
        if not vendor_key:
            continue
        existing = latest_submitted_assessments.get(vendor_key)
        if existing is None or (
            (assessment.get("vendor_assessment_date", ""), assessment.get("submitted_date", ""), assessment.get("id", 0))
            > (existing.get("vendor_assessment_date", ""), existing.get("submitted_date", ""), existing.get("id", 0))
        ):
            latest_submitted_assessments[vendor_key] = assessment

    with get_db_connection() as connection:
        for vendor in vendor_catalog:
            vendor_name = vendor.get("vendor_name", "").strip()
            if not vendor_name:
                continue
            connection.execute(
                """
                INSERT INTO vendor_entities (name, country_of_origin, data)
                VALUES (?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    country_of_origin = excluded.country_of_origin,
                    data = excluded.data
                """,
                (
                    vendor_name,
                    vendor.get("vendor_country", "").strip(),
                    json.dumps({field: vendor.get(field, "") for field in VENDOR_PROFILE_FIELDS}),
                ),
            )

        if vendor_names:
            placeholders = ", ".join("?" for _ in vendor_names)
            connection.execute(
                f"DELETE FROM vendor_entities WHERE name NOT IN ({placeholders})",
                vendor_names,
            )
        else:
            connection.execute("DELETE FROM vendor_entities")

        vendor_rows = connection.execute("SELECT id, name FROM vendor_entities").fetchall()
        vendor_id_by_name = {
            normalized_name(row["name"]): row["id"]
            for row in vendor_rows
        }
        country_id_by_name = {
            row["name"]: row["id"]
            for row in connection.execute("SELECT id, name FROM data_storage_countries").fetchall()
        }

        connection.execute("DELETE FROM vendor_data_storage_countries")
        vendor_country_rows = []
        for vendor in vendor_catalog:
            vendor_key = normalized_name(vendor.get("vendor_name", ""))
            vendor_id = vendor_id_by_name.get(vendor_key)
            latest_assessment = latest_submitted_assessments.get(vendor_key)
            if vendor_id is None or latest_assessment is None:
                continue

            for country_name in get_selected_values(latest_assessment.get("data_storage_location", "")):
                country_id = country_id_by_name.get(country_name)
                if country_id is not None:
                    vendor_country_rows.append((vendor_id, country_id))

        connection.executemany(
            """
            INSERT INTO vendor_data_storage_countries (vendor_id, country_id)
            VALUES (?, ?)
            """,
            vendor_country_rows,
        )


def load_software_records():
    with get_db_connection() as connection:
        rows = connection.execute("SELECT id, data FROM assessments ORDER BY id").fetchall()

    records = []
    for row in rows:
        loaded_record = json.loads(row["data"])
        record = blank_assessment()
        for field in ASSESSMENT_FIELDS:
            if field in loaded_record:
                record[field] = loaded_record[field]
        for field in VENDOR_PRIVACY_FIELDS:
            if field in loaded_record:
                record[field] = loaded_record[field]
        if record["is_assessment"] and not record.get("submission_status"):
            record["submission_status"] = "submitted"
        if record.get("submission_status") == "submitted":
            if not record.get("submitted_date") and record.get("assessment_date"):
                record["submitted_date"] = record["assessment_date"]
            if record.get("submitted_date") and not record.get("assessment_date"):
                record["assessment_date"] = record["submitted_date"]
        normalize_privacy_fields(record)
        legacy_website = str(loaded_record.get("website", "")).strip()
        if legacy_website:
            if not record["software_website"]:
                record["software_website"] = legacy_website
            if not record["vendor_website"]:
                record["vendor_website"] = legacy_website
        record["id"] = row["id"]
        normalize_submitted_audit_dates(record)
        records.append(enrich_assessment(record))
    return records


def load_software_items():
    with get_db_connection() as connection:
        rows = connection.execute("SELECT id, vendor_name, software_name, data FROM software ORDER BY id").fetchall()

    records = []
    for row in rows:
        loaded_record = json.loads(row["data"])
        record = blank_assessment()
        for field in ASSESSMENT_FIELDS:
            if field in loaded_record:
                record[field] = loaded_record[field]
        record["deployed"] = bool(loaded_record["deployed"]) if "deployed" in loaded_record else True
        record["tested"] = bool(loaded_record.get("tested", False))
        record["risk_level"] = normalize_risk_level(loaded_record.get("risk_level", ""))
        record["software_type"] = loaded_record.get("software_type", "")
        record["support_notes"] = loaded_record.get("support_notes", "")
        record["software_support"] = loaded_record.get("software_support", "")
        record["eula_pdf_filename"] = loaded_record.get("eula_pdf_filename", "")
        record["eula_pdf_original_name"] = loaded_record.get("eula_pdf_original_name", "")
        record["id"] = row["id"]
        record["software_id"] = row["id"]
        record["software_name"] = record.get("software_name") or row["software_name"]
        record["vendor_name"] = record.get("vendor_name") or row["vendor_name"]
        record["is_assessment"] = False
        record["submission_status"] = ""
        records.append(enrich_assessment(record))
    return records


def load_software_assessment_records(software_items=None):
    software_id_by_name = {
        normalized_name(record.get("software_name", "")): record.get("id")
        for record in software_items or []
        if record.get("software_name")
    }

    with get_db_connection() as connection:
        rows = connection.execute(
            "SELECT id, software_id, software_name, data FROM software_assessments ORDER BY id"
        ).fetchall()

    records = []
    for row in rows:
        loaded_record = json.loads(row["data"])
        record = blank_assessment()
        for field in ASSESSMENT_FIELDS:
            if field in loaded_record:
                record[field] = loaded_record[field]
        record["deployed"] = bool(loaded_record["deployed"]) if "deployed" in loaded_record else True
        record["tested"] = bool(loaded_record.get("tested", False))
        record["id"] = row["id"]
        record["software_name"] = record.get("software_name") or row["software_name"]
        record["software_id"] = record.get("software_id") or row["software_id"] or software_id_by_name.get(
            normalized_name(record.get("software_name", ""))
        )
        record["is_assessment"] = True
        if not record.get("submission_status"):
            record["submission_status"] = "submitted"
        normalize_submitted_audit_dates(record)
        records.append(enrich_assessment(record))
    return records


def compose_software_records():
    return [*SOFTWARE_ITEMS, *SOFTWARE_ASSESSMENT_RECORDS]


def find_software_id(software_name):
    normalized = normalized_name(software_name)
    if not normalized:
        return None

    for record in SOFTWARE_ITEMS:
        if normalized_name(record.get("software_name", "")) == normalized:
            return record.get("id")
    return None


def ensure_software_item_for_record(record):
    software_name = record.get("software_name", "").strip()
    if not software_name:
        return None

    existing_id = find_software_id(software_name)
    if existing_id is not None:
        return existing_id

    next_id = max((item.get("id", 0) for item in SOFTWARE_ITEMS), default=0) + 1
    software = blank_assessment()
    for field in SOFTWARE_DETAIL_FIELDS:
        if field in record:
            software[field] = record.get(field, "")
    for field in ("vendor_website", "vendor_terms_conditions_link", "vendor_privacy_policy_link", "online_support"):
        software[field] = record.get(field, "")
    software["id"] = next_id
    software["software_id"] = next_id
    software["is_assessment"] = False
    software["submission_status"] = ""
    software["deployed"] = True
    SOFTWARE_ITEMS.append(enrich_assessment(software))
    return next_id


def _software_record_to_json(record):
    data = {key: record.get(key) for key in ASSESSMENT_FIELDS if key != "id"}
    data["deployed"] = bool(record.get("deployed", False))
    data["tested"] = bool(record.get("tested", False))
    data["risk_level"] = record.get("risk_level", "")
    data["software_type"] = record.get("software_type", "")
    data["support_notes"] = record.get("support_notes", "")
    data["software_support"] = record.get("software_support", "")
    data["eula_pdf_filename"] = record.get("eula_pdf_filename", "")
    data["eula_pdf_original_name"] = record.get("eula_pdf_original_name", "")
    return json.dumps(data)


def persist_software_items():
    with get_db_connection() as connection:
        connection.execute("DELETE FROM software")
        connection.executemany(
            "INSERT INTO software (id, vendor_name, software_name, data) VALUES (?, ?, ?, ?)",
            [
                (
                    int(record["id"]),
                    record.get("vendor_name", ""),
                    record.get("software_name", ""),
                    _software_record_to_json(record),
                )
                for record in SOFTWARE_ITEMS
                if record.get("id") and record.get("software_name")
            ],
        )


def persist_software_assessment_records():
    with get_db_connection() as connection:
        connection.execute("DELETE FROM software_assessments")
        connection.executemany(
            "INSERT INTO software_assessments (id, software_id, software_name, data) VALUES (?, ?, ?, ?)",
            [
                (
                    int(record["id"]),
                    record.get("software_id") or find_software_id(record.get("software_name", "")),
                    record.get("software_name", ""),
                    _software_record_to_json(record),
                )
                for record in SOFTWARE_ASSESSMENT_RECORDS
                if record.get("id") and record.get("software_name")
            ],
        )


def persist_legacy_assessment_records():
    used_legacy_ids = set()
    next_legacy_id = max((int(record["id"]) for record in SOFTWARE_RECORDS if record.get("id")), default=0) + 1
    legacy_rows = []
    for record in SOFTWARE_RECORDS:
        if not record.get("id"):
            continue

        legacy_id = int(record["id"])
        if legacy_id in used_legacy_ids:
            legacy_id = next_legacy_id
            next_legacy_id += 1

        used_legacy_ids.add(legacy_id)
        legacy_rows.append(
            (
                legacy_id,
                json.dumps({key: record.get(key) for key in ASSESSMENT_FIELDS if key != "id"}),
            )
        )

    with get_db_connection() as connection:
        connection.execute("DELETE FROM assessments")
        connection.executemany(
            "INSERT INTO assessments (id, data) VALUES (?, ?)",
            legacy_rows,
        )


def persist_software_records():
    global SOFTWARE_ITEMS, SOFTWARE_ASSESSMENT_RECORDS, SOFTWARE_RECORDS

    SOFTWARE_ITEMS = [record for record in SOFTWARE_RECORDS if not record.get("is_assessment")]
    SOFTWARE_ASSESSMENT_RECORDS = [record for record in SOFTWARE_RECORDS if record.get("is_assessment")]

    for record in SOFTWARE_ITEMS:
        record["software_id"] = record.get("software_id") or record.get("id")

    for record in SOFTWARE_ASSESSMENT_RECORDS:
        record["software_id"] = record.get("software_id") or ensure_software_item_for_record(record)

    SOFTWARE_RECORDS = compose_software_records()
    persist_software_items()
    persist_software_assessment_records()
    persist_legacy_assessment_records()
    sync_data_storage_reference_tables()
    sync_vendor_entity_tables()


def migrate_legacy_software_records_if_needed():
    global SOFTWARE_ITEMS, SOFTWARE_ASSESSMENT_RECORDS, SOFTWARE_RECORDS

    if SOFTWARE_ITEMS or SOFTWARE_ASSESSMENT_RECORDS:
        return False

    legacy_records = load_software_records()
    if not legacy_records:
        return False

    software_by_name = {}
    next_software_id = max((record.get("id", 0) for record in legacy_records), default=0) + 1
    for record in sorted(
        legacy_records,
        key=lambda item: (not bool(item.get("is_assessment")), item.get("assessment_date", ""), item.get("id", 0)),
        reverse=True,
    ):
        software_name = record.get("software_name", "").strip()
        if not software_name:
            continue

        key = normalized_name(software_name)
        if key in software_by_name:
            continue

        software = blank_assessment()
        for field in SOFTWARE_DETAIL_FIELDS:
            if field in record:
                software[field] = record.get(field, "")
        for field in ("vendor_website", "vendor_terms_conditions_link", "vendor_privacy_policy_link", "online_support"):
            software[field] = record.get(field, "")
        if record.get("is_assessment"):
            software["id"] = next_software_id
            next_software_id += 1
        else:
            software["id"] = record["id"]
        software["software_id"] = software["id"]
        software["is_assessment"] = False
        software["submission_status"] = ""
        software_by_name[key] = enrich_assessment(software)

    SOFTWARE_ITEMS = list(software_by_name.values())
    for record in legacy_records:
        if not record.get("is_assessment"):
            continue
        software_id = find_software_id(record.get("software_name", ""))
        if software_id is None:
            software_id = ensure_software_item_for_record(record)
        record["software_id"] = software_id
        SOFTWARE_ASSESSMENT_RECORDS.append(record)

    SOFTWARE_RECORDS = compose_software_records()
    persist_software_records()
    return True


def load_vendor_records():
    with get_db_connection() as connection:
        rows = connection.execute("SELECT name, data FROM vendors ORDER BY name").fetchall()

    vendors = []
    for row in rows:
        loaded_vendor = json.loads(row["data"])
        vendor = {
            "vendor_name": loaded_vendor.get("vendor_name") or row["name"],
            "vendor_country": loaded_vendor.get("vendor_country", ""),
            "vendor_website": loaded_vendor.get("vendor_website", "") or loaded_vendor.get("website", ""),
            "vendor_terms_conditions_link": loaded_vendor.get("vendor_terms_conditions_link", ""),
            "no_vendor_terms_conditions": bool(loaded_vendor.get("no_vendor_terms_conditions", False)),
            "vendor_cookie_policy_link": loaded_vendor.get("vendor_cookie_policy_link", ""),
            "vendor_privacy_policy_link": loaded_vendor.get("vendor_privacy_policy_link", ""),
            "online_support": loaded_vendor.get("online_support", ""),
            "vendor_audit_reminder_frequency": loaded_vendor.get("vendor_audit_reminder_frequency", "") or "1_year",
            "vendor_next_audit_date": loaded_vendor.get("vendor_next_audit_date", ""),
            "vendor_age_restrictions": loaded_vendor.get("vendor_age_restrictions", ""),
            "vendor_terms_conditions_notes": loaded_vendor.get("vendor_terms_conditions_notes", ""),
            "vendor_allows_acceptance_on_behalf_of_entity": loaded_vendor.get("vendor_allows_acceptance_on_behalf_of_entity", ""),
            "privacy_policy_pdf_filename": loaded_vendor.get("privacy_policy_pdf_filename", ""),
            "privacy_policy_pdf_original_name": loaded_vendor.get("privacy_policy_pdf_original_name", ""),
            "vendor_tc_pdf_filename": loaded_vendor.get("vendor_tc_pdf_filename", ""),
            "vendor_tc_pdf_original_name": loaded_vendor.get("vendor_tc_pdf_original_name", ""),
        }
        for field in ("vendor_security_assessment", *VENDOR_PRIVACY_FIELDS):
            if loaded_vendor.get(field):
                vendor[field] = loaded_vendor.get(field, "")
        vendors.append(vendor)
    return vendors


def persist_vendor_records():
    # Deduplicate in-memory list by normalised name (last write wins)
    seen: dict = {}
    for vendor in VENDOR_RECORDS:
        key = normalized_name(vendor.get("vendor_name", ""))
        if key:
            seen[key] = vendor
    VENDOR_RECORDS[:] = list(seen.values())

    with get_db_connection() as connection:
        connection.execute("DELETE FROM vendors")
        connection.executemany(
            "INSERT INTO vendors (name, data) VALUES (?, ?)",
            [
                (
                    vendor["vendor_name"],
                    json.dumps({field: vendor.get(field, "") for field in VENDOR_PROFILE_FIELDS}),
                )
                for vendor in VENDOR_RECORDS
                if vendor.get("vendor_name")
            ],
        )
    sync_vendor_entity_tables()


def blank_vendor_assessment(vendor_name=""):
    assessment = {field: "" for field in VENDOR_ASSESSMENT_FIELDS}
    assessment["vendor_name"] = vendor_name
    assessment["vendor_audit_reminder_frequency"] = "1_year"
    assessment["submission_status"] = "submitted"
    return assessment


def normalize_vendor_assessment(record):
    normalized = blank_vendor_assessment(record.get("vendor_name", ""))
    if record.get("id") is not None:
        normalized["id"] = record.get("id")
    for field in VENDOR_ASSESSMENT_FIELDS:
        if field in record:
            normalized[field] = record.get(field, "")
    normalize_privacy_fields(normalized)
    if not normalized.get("cloud_hosted_data") and normalized.get("data_types_stored"):
        normalized["cloud_hosted_data"] = "Yes"
    normalized["vendor_assessment_date"] = normalized.get("vendor_assessment_date") or normalized.get("submitted_date", "")
    if not normalized.get("submission_status"):
        normalized["submission_status"] = "submitted"
    if normalized.get("submission_status") == "submitted" and not normalized.get("submitted_date"):
        normalized["submitted_date"] = normalized.get("vendor_assessment_date", "")
    normalized["vendor_next_audit_date"] = normalized.get("vendor_next_audit_date") or calculate_next_audit_date_from_assessment(
        normalized.get("vendor_assessment_date", ""),
        normalized.get("vendor_audit_reminder_frequency", ""),
    )
    return normalized


def enrich_vendor_assessment(record):
    enriched = normalize_vendor_assessment(record)
    try:
        next_audit_date = datetime.strptime(enriched.get("vendor_next_audit_date", ""), "%Y-%m-%d").date()
    except ValueError:
        next_audit_date = None

    today = date.today()
    enriched["is_overdue"] = bool(next_audit_date and next_audit_date < today)
    enriched["overdue_label"] = (
        f"Overdue by {describe_overdue_duration((today - next_audit_date).days)}"
        if next_audit_date and next_audit_date < today
        else ""
    )
    return enriched


def load_vendor_assessment_records():
    with get_db_connection() as connection:
        rows = connection.execute("SELECT id, vendor_name, data FROM vendor_assessments ORDER BY id").fetchall()

    records = []
    for row in rows:
        loaded_record = json.loads(row["data"])
        loaded_record["id"] = row["id"]
        loaded_record["vendor_name"] = loaded_record.get("vendor_name") or row["vendor_name"]
        records.append(enrich_vendor_assessment(loaded_record))
    return records


def persist_vendor_assessment_records():
    with get_db_connection() as connection:
        connection.execute("DELETE FROM vendor_assessments")
        connection.executemany(
            "INSERT INTO vendor_assessments (id, vendor_name, data) VALUES (?, ?, ?)",
            [
                (
                    int(record["id"]),
                    record.get("vendor_name", ""),
                    json.dumps({field: record.get(field, "") for field in VENDOR_ASSESSMENT_FIELDS}),
                )
                for record in VENDOR_ASSESSMENT_RECORDS
                if record.get("id") and record.get("vendor_name")
            ],
        )
    sync_data_storage_reference_tables()
    sync_vendor_entity_tables()


def load_app_settings():
    settings = dict(DEFAULT_APP_SETTINGS)
    with get_db_connection() as connection:
        rows = connection.execute("SELECT key, value FROM settings").fetchall()

    for row in rows:
        settings[row["key"]] = row["value"]
    settings["country_risk_assignments"] = json.dumps(
        normalize_country_risk_assignments(settings.get("country_risk_assignments", "{}"))
    )
    settings["signatory_alerts"] = json.dumps(
        normalize_signatory_alerts(settings.get("signatory_alerts", "{}"))
    )
    default_alert_risk_levels = normalize_alert_risk_levels(DEFAULT_APP_SETTINGS["alert_risk_levels"])
    loaded_alert_risk_levels = normalize_alert_risk_levels(settings.get("alert_risk_levels", "{}"))
    merged = {**default_alert_risk_levels, **loaded_alert_risk_levels}
    settings["alert_risk_levels"] = json.dumps(merged)
    return settings


def persist_app_settings():
    with get_db_connection() as connection:
        connection.execute("DELETE FROM settings")
        connection.executemany(
            "INSERT INTO settings (key, value) VALUES (?, ?)",
            [(key, str(value)) for key, value in APP_SETTINGS.items()],
        )


@app.context_processor
def inject_app_theme_settings():
    return {
        "dark_mode_enabled": is_dark_mode_enabled(),
    }


def migrate_privacy_fields_to_vendor_assessment_records():
    changed = False
    vendors_by_name = {
        normalized_name(vendor.get("vendor_name", "")): vendor
        for vendor in VENDOR_RECORDS
        if vendor.get("vendor_name", "").strip()
    }
    vendor_assessments_by_name = {
        normalized_name(assessment.get("vendor_name", ""))
        for assessment in VENDOR_ASSESSMENT_RECORDS
        if assessment.get("vendor_name", "").strip()
    }
    next_vendor_assessment_id = max(
        (assessment["id"] for assessment in VENDOR_ASSESSMENT_RECORDS if assessment.get("id")),
        default=0,
    ) + 1

    for record in sorted(
        SOFTWARE_RECORDS,
        key=lambda item: (bool(item.get("is_assessment")), item.get("assessment_date", ""), item.get("id", 0)),
        reverse=True,
    ):
        vendor_name = record.get("vendor_name", "").strip()
        if not vendor_name:
            continue

        vendor_key = normalized_name(vendor_name)
        vendor = vendors_by_name.get(vendor_key)
        if vendor is None:
            vendor = {
                "vendor_name": vendor_name,
                "vendor_country": record.get("vendor_country", "").strip(),
                "vendor_website": record.get("vendor_website", "").strip(),
                "vendor_terms_conditions_link": record.get("vendor_terms_conditions_link", "").strip(),
                "vendor_privacy_policy_link": record.get("vendor_privacy_policy_link", "").strip(),
                "online_support": record.get("online_support", "").strip(),
            }
            VENDOR_RECORDS.append(vendor)
            vendors_by_name[vendor_key] = vendor
            changed = True

        if (
            any(record.get(field) for field in VENDOR_PRIVACY_FIELDS)
            and vendor_key not in vendor_assessments_by_name
        ):
            legacy_assessment = {
                "id": next_vendor_assessment_id,
                "vendor_name": vendor_name,
                "vendor_assessment_date": record.get("assessment_date") or record.get("submitted_date") or date.today().isoformat(),
                "submitted_date": record.get("submitted_date") or record.get("assessment_date") or date.today().isoformat(),
                "vendor_security_assessment": record.get("vendor_security_assessment", "").strip(),
                "vendor_audit_reminder_frequency": record.get("audit_reminder_frequency", "") or "1_year",
            }
            for field in VENDOR_PRIVACY_FIELDS:
                legacy_assessment[field] = record.get(field, "")
            legacy_assessment = enrich_vendor_assessment(legacy_assessment)
            VENDOR_ASSESSMENT_RECORDS.append(legacy_assessment)
            vendor_assessments_by_name.add(vendor_key)
            next_vendor_assessment_id += 1
            changed = True

    for record in SOFTWARE_RECORDS:
        for field in VENDOR_PRIVACY_FIELDS:
            if field in record:
                record.pop(field, None)
                changed = True
        record.update(enrich_assessment(record))

    for vendor in VENDOR_RECORDS:
        vendor_name = vendor.get("vendor_name", "").strip()
        if not vendor_name:
            continue

        legacy_assessment = {
            "vendor_name": vendor_name,
            "vendor_assessment_date": date.today().isoformat(),
            "submitted_date": date.today().isoformat(),
            "vendor_security_assessment": vendor.get("vendor_security_assessment", ""),
            "vendor_audit_reminder_frequency": "1_year",
        }
        for field in VENDOR_PRIVACY_FIELDS:
            legacy_assessment[field] = vendor.get(field, "")

        if (
            any(legacy_assessment.get(field) for field in ("vendor_security_assessment", *VENDOR_PRIVACY_FIELDS))
            and normalized_name(vendor_name) not in vendor_assessments_by_name
        ):
            legacy_assessment["id"] = next_vendor_assessment_id
            next_vendor_assessment_id += 1
            legacy_assessment = enrich_vendor_assessment(legacy_assessment)
            VENDOR_ASSESSMENT_RECORDS.append(legacy_assessment)
            vendor_assessments_by_name.add(normalized_name(vendor_name))
            changed = True

        for field in ("vendor_security_assessment", *VENDOR_PRIVACY_FIELDS):
            if field in vendor:
                vendor.pop(field, None)
                changed = True

    return changed


def load_categories():
    with get_db_connection() as connection:
        rows = connection.execute(
            "SELECT id, name, genuine_need FROM categories ORDER BY name"
        ).fetchall()
    return [{"id": row["id"], "name": row["name"], "genuine_need": row["genuine_need"]} for row in rows]


def persist_categories():
    with get_db_connection() as connection:
        connection.execute("DELETE FROM categories")
        connection.executemany(
            "INSERT INTO categories (id, name, genuine_need) VALUES (?, ?, ?)",
            [(cat["id"], cat["name"], cat["genuine_need"]) for cat in CATEGORIES],
        )


def get_category_by_name(name):
    normalized = name.strip().casefold()
    for cat in CATEGORIES:
        if cat["name"].casefold() == normalized:
            return cat
    return None


def refresh_runtime_state():
    global SOFTWARE_ITEMS, SOFTWARE_ASSESSMENT_RECORDS, SOFTWARE_RECORDS, VENDOR_RECORDS, VENDOR_ASSESSMENT_RECORDS
    global APP_SETTINGS, NEXT_SOFTWARE_ID, NEXT_ASSESSMENT_ID, NEXT_VENDOR_ASSESSMENT_ID
    global CATEGORIES, NEXT_CATEGORY_ID

    SOFTWARE_ITEMS = load_software_items()
    SOFTWARE_ASSESSMENT_RECORDS = load_software_assessment_records(SOFTWARE_ITEMS)
    SOFTWARE_RECORDS = compose_software_records()
    migrate_legacy_software_records_if_needed()
    VENDOR_RECORDS = load_vendor_records()
    VENDOR_ASSESSMENT_RECORDS = load_vendor_assessment_records()
    APP_SETTINGS = load_app_settings()
    if migrate_privacy_fields_to_vendor_assessment_records():
        persist_software_records()
        persist_vendor_records()
        persist_vendor_assessment_records()
    sync_data_storage_reference_tables()
    sync_vendor_entity_tables()
    NEXT_SOFTWARE_ID = max((record["id"] for record in SOFTWARE_ITEMS), default=0) + 1
    NEXT_ASSESSMENT_ID = max((record["id"] for record in SOFTWARE_ASSESSMENT_RECORDS), default=0) + 1
    NEXT_VENDOR_ASSESSMENT_ID = max((record.get("id", 0) for record in VENDOR_ASSESSMENT_RECORDS), default=0) + 1
    CATEGORIES = load_categories()
    NEXT_CATEGORY_ID = max((cat["id"] for cat in CATEGORIES), default=0) + 1


init_db()
refresh_runtime_state()


@app.before_request
def require_login():
    allowed_endpoints = {"login", "static"}
    if request.endpoint in allowed_endpoints:
        return None

    if session.get("authenticated"):
        return None

    return redirect(url_for("login", next=request.path))


def build_vendor_list(active_only=False):
    vendors_by_name = {}

    item_fields_by_name = {
        normalized_name(item.get("software_name", "")): item
        for item in SOFTWARE_ITEMS
        if item.get("software_name")
    }
    latest_by_name = {}
    for record in SOFTWARE_RECORDS:
        software_name = record.get("software_name", "").strip()
        if not software_name:
            continue
        key = normalized_name(software_name)
        current = latest_by_name.get(key)
        record_rank = (bool(record.get("is_assessment")), record.get("assessment_date", ""), record.get("id", 0))
        if current is None:
            latest_by_name[key] = record
            continue
        current_rank = (bool(current.get("is_assessment")), current.get("assessment_date", ""), current.get("id", 0))
        if record_rank > current_rank:
            latest_by_name[key] = record

    software_records_for_vendors = []
    for key, record in latest_by_name.items():
        if active_only:
            item = item_fields_by_name.get(key, {})
            if not bool(item.get("deployed", True)):
                continue
        software_records_for_vendors.append(record)

    for record in software_records_for_vendors:
        vendor_name = record.get("vendor_name", "").strip()
        if not vendor_name:
            continue
        vendor = vendors_by_name.setdefault(
            vendor_name,
            {
                "vendor_name": vendor_name,
                "vendor_country": record["vendor_country"],
                "vendor_website": record.get("vendor_website", ""),
                "vendor_terms_conditions_link": record.get("vendor_terms_conditions_link", ""),
                "vendor_cookie_policy_link": "",
                "vendor_privacy_policy_link": record.get("vendor_privacy_policy_link", ""),
                "online_support": record.get("online_support", ""),
                "vendor_audit_reminder_frequency": record.get("vendor_audit_reminder_frequency", "") or "1_year",
                "vendor_next_audit_date": record.get("vendor_next_audit_date", ""),
                "vendor_age_restrictions": "",
                "vendor_terms_conditions_notes": "",
                "vendor_allows_acceptance_on_behalf_of_entity": "",
                "product_count": 0,
            },
        )
        vendor["vendor_country"] = vendor["vendor_country"] or record["vendor_country"]
        vendor["vendor_website"] = vendor["vendor_website"] or record.get("vendor_website", "")
        vendor["vendor_terms_conditions_link"] = vendor["vendor_terms_conditions_link"] or record.get("vendor_terms_conditions_link", "")
        vendor["vendor_privacy_policy_link"] = vendor["vendor_privacy_policy_link"] or record.get("vendor_privacy_policy_link", "")
        vendor["online_support"] = vendor["online_support"] or record.get("online_support", "")
        vendor["vendor_audit_reminder_frequency"] = vendor.get("vendor_audit_reminder_frequency") or record.get("vendor_audit_reminder_frequency", "") or "1_year"
        vendor["vendor_next_audit_date"] = vendor.get("vendor_next_audit_date") or record.get("vendor_next_audit_date", "")
        vendor["product_count"] += 1

    for vendor in VENDOR_RECORDS:
        vendor_name = vendor.get("vendor_name", "").strip()
        if not vendor_name:
            continue
        if active_only and vendor_name not in vendors_by_name:
            continue
        existing = vendors_by_name.setdefault(
            vendor_name,
            {
                "vendor_name": vendor_name,
                "vendor_country": vendor["vendor_country"],
                "vendor_website": vendor.get("vendor_website", ""),
                "vendor_terms_conditions_link": vendor.get("vendor_terms_conditions_link", ""),
                "vendor_cookie_policy_link": vendor.get("vendor_cookie_policy_link", ""),
                "vendor_privacy_policy_link": vendor.get("vendor_privacy_policy_link", ""),
                "online_support": vendor.get("online_support", ""),
                "vendor_audit_reminder_frequency": vendor.get("vendor_audit_reminder_frequency", "") or "1_year",
                "vendor_next_audit_date": vendor.get("vendor_next_audit_date", ""),
                "vendor_age_restrictions": vendor.get("vendor_age_restrictions", ""),
                "vendor_terms_conditions_notes": vendor.get("vendor_terms_conditions_notes", ""),
                "vendor_allows_acceptance_on_behalf_of_entity": vendor.get("vendor_allows_acceptance_on_behalf_of_entity", ""),
                "no_vendor_terms_conditions": vendor.get("no_vendor_terms_conditions", False),
                "product_count": 0,
            },
        )
        existing["vendor_country"] = existing["vendor_country"] or vendor["vendor_country"]
        existing["vendor_website"] = existing["vendor_website"] or vendor.get("vendor_website", "")
        existing["vendor_terms_conditions_link"] = existing["vendor_terms_conditions_link"] or vendor.get("vendor_terms_conditions_link", "")
        existing["vendor_cookie_policy_link"] = existing.get("vendor_cookie_policy_link") or vendor.get("vendor_cookie_policy_link", "")
        existing["vendor_privacy_policy_link"] = existing["vendor_privacy_policy_link"] or vendor.get("vendor_privacy_policy_link", "")
        existing["online_support"] = existing["online_support"] or vendor.get("online_support", "")
        existing["vendor_audit_reminder_frequency"] = existing.get("vendor_audit_reminder_frequency") or vendor.get("vendor_audit_reminder_frequency", "") or "1_year"
        existing["vendor_next_audit_date"] = existing.get("vendor_next_audit_date") or vendor.get("vendor_next_audit_date", "")
        existing["vendor_age_restrictions"] = existing.get("vendor_age_restrictions") or vendor.get("vendor_age_restrictions", "")
        existing["vendor_terms_conditions_notes"] = existing.get("vendor_terms_conditions_notes") or vendor.get("vendor_terms_conditions_notes", "")
        existing["vendor_allows_acceptance_on_behalf_of_entity"] = existing.get("vendor_allows_acceptance_on_behalf_of_entity") or vendor.get("vendor_allows_acceptance_on_behalf_of_entity", "")
        existing["no_vendor_terms_conditions"] = existing.get("no_vendor_terms_conditions") or vendor.get("no_vendor_terms_conditions", False)
        existing["privacy_policy_pdf_filename"] = existing.get("privacy_policy_pdf_filename") or vendor.get("privacy_policy_pdf_filename", "")
        existing["privacy_policy_pdf_original_name"] = existing.get("privacy_policy_pdf_original_name") or vendor.get("privacy_policy_pdf_original_name", "")
        existing["vendor_tc_pdf_filename"] = existing.get("vendor_tc_pdf_filename") or vendor.get("vendor_tc_pdf_filename", "")
        existing["vendor_tc_pdf_original_name"] = existing.get("vendor_tc_pdf_original_name") or vendor.get("vendor_tc_pdf_original_name", "")

    built_vendors = []
    for vendor_name in sorted(vendors_by_name):
        vendor = vendors_by_name[vendor_name]
        built_vendors.append(
            {
                "vendor_name": vendor["vendor_name"],
                "vendor_country": vendor["vendor_country"],
                "vendor_website": vendor.get("vendor_website", ""),
                "vendor_terms_conditions_link": vendor.get("vendor_terms_conditions_link", ""),
                "vendor_cookie_policy_link": vendor.get("vendor_cookie_policy_link", ""),
                "vendor_privacy_policy_link": vendor.get("vendor_privacy_policy_link", ""),
                "online_support": vendor.get("online_support", ""),
                "vendor_audit_reminder_frequency": vendor.get("vendor_audit_reminder_frequency", "") or "1_year",
                "vendor_next_audit_date": vendor.get("vendor_next_audit_date", ""),
                "vendor_age_restrictions": vendor.get("vendor_age_restrictions", ""),
                "vendor_terms_conditions_notes": vendor.get("vendor_terms_conditions_notes", ""),
                "vendor_allows_acceptance_on_behalf_of_entity": vendor.get("vendor_allows_acceptance_on_behalf_of_entity", ""),
                "no_vendor_terms_conditions": vendor.get("no_vendor_terms_conditions", False),
                "privacy_policy_pdf_filename": vendor.get("privacy_policy_pdf_filename", ""),
                "privacy_policy_pdf_original_name": vendor.get("privacy_policy_pdf_original_name", ""),
                "vendor_tc_pdf_filename": vendor.get("vendor_tc_pdf_filename", ""),
                "vendor_tc_pdf_original_name": vendor.get("vendor_tc_pdf_original_name", ""),
                "product_count": vendor["product_count"],
            }
        )

    return built_vendors


def get_assessment_or_none(assessment_id):
    for record in SOFTWARE_ASSESSMENT_RECORDS:
        if record["id"] == assessment_id:
            return record
    return None


def get_software_record_or_none(record_id):
    for record in SOFTWARE_ITEMS:
        if record["id"] == record_id:
            return record
    for record in SOFTWARE_ASSESSMENT_RECORDS:
        if record["id"] == record_id:
            return record
    return None


def get_software_records(software_name):
    normalized = normalized_name(software_name)
    if not normalized:
        return []

    records = [
        record for record in SOFTWARE_RECORDS
        if normalized_name(record.get("software_name", "")) == normalized
    ]
    return sorted(
        records,
        key=lambda record: (bool(record.get("is_assessment")), record.get("assessment_date", ""), record.get("id", 0)),
        reverse=True,
    )


def get_software_history(software_name):
    return [record for record in get_software_assessment_records(software_name) if is_submitted_assessment(record)]


def get_software_assessment_records(software_name):
    normalized = normalized_name(software_name)
    if not normalized:
        return []

    records = [
        record for record in SOFTWARE_ASSESSMENT_RECORDS
        if normalized_name(record.get("software_name", "")) == normalized
    ]
    return sorted(
        records,
        key=lambda record: (record.get("assessment_date", ""), record.get("id", 0)),
        reverse=True,
    )


def get_latest_software_record(software_name):
    records = get_software_records(software_name)
    return records[0] if records else None


def build_software_catalog(active_only=False):
    item_fields_by_name = {
        normalized_name(item.get("software_name", "")): item
        for item in SOFTWARE_ITEMS
        if item.get("software_name")
    }

    latest_by_name = {}

    for record in SOFTWARE_RECORDS:
        software_name = record.get("software_name", "").strip()
        if not software_name:
            continue
        key = normalized_name(software_name)
        current = latest_by_name.get(key)
        record_rank = (bool(record.get("is_assessment")), record.get("assessment_date", ""), record.get("id", 0))
        if current is None:
            latest_by_name[key] = record
            continue
        current_rank = (bool(current.get("is_assessment")), current.get("assessment_date", ""), current.get("id", 0))
        if record_rank > current_rank:
            latest_by_name[key] = record

    home_country = get_home_country()
    vendor_by_name = {
        normalized_name(v.get("vendor_name", "")): v
        for v in build_vendor_list()
        if v.get("vendor_name")
    }

    result = []
    for key, record in latest_by_name.items():
        item = item_fields_by_name.get(key, {})
        is_deployed = bool(item.get("deployed", True))
        if active_only and not is_deployed:
            continue
        annotated = dict(record)
        annotated["deployed"] = is_deployed
        # These fields live on the software item, not per-assessment
        annotated["next_audit_date"] = item.get("next_audit_date", "") or record.get("next_audit_date", "")
        annotated["audit_reminder_frequency"] = item.get("audit_reminder_frequency", "") or record.get("audit_reminder_frequency", "")
        annotated["category"] = item.get("category", "") or record.get("category", "")
        if item:
            annotated["product_updates"] = item.get("product_updates", False)
            annotated["security_updates"] = item.get("security_updates", False)
            annotated["support_notes"] = item.get("support_notes", "")
            annotated["tested"] = item.get("tested", False)
            annotated["software_type"] = item.get("software_type", record.get("software_type", ""))
        vendor_name = record.get("vendor_name", "").strip()
        vendor_record = vendor_by_name.get(normalized_name(vendor_name)) if vendor_name else None
        vendor_map = build_vendor_data_storage_map(vendor_name) if vendor_name else {
            "high_risk_locations": [], "locations": [], "no_privacy_policy": False, "dpa_status": "",
        }
        alert_keys = compute_software_alert_keys(annotated, vendor_record, vendor_map, home_country, item)
        computed_risk = highest_risk_from_alerts(alert_keys)
        if not computed_risk and annotated.get("is_assessment"):
            computed_risk = "Low"
        annotated["risk_level"] = computed_risk
        result.append(annotated)
    return sorted(result, key=lambda record: normalized_name(record.get("software_name", "")))


def delete_software_details(software_name):
    normalized = normalized_name(software_name)
    if not normalized:
        return

    SOFTWARE_RECORDS[:] = [
        record for record in SOFTWARE_RECORDS
        if normalized_name(record.get("software_name", "")) != normalized
    ]

    persist_software_records()


def update_software_audit_date(software_name, next_audit_date):
    normalized = normalized_name(software_name)
    if not normalized:
        return

    for record in SOFTWARE_RECORDS:
        if normalized_name(record.get("software_name", "")) == normalized:
            record["next_audit_date"] = next_audit_date
            record["review_date"] = next_audit_date or calculate_review_date(
                record.get("deployment_date", ""),
                record.get("audit_reminder_frequency", ""),
            )
            record.update(enrich_assessment(record))

    persist_software_records()


def advance_software_next_audit_after_submission(assessment_record):
    software_name = assessment_record.get("software_name", "")
    normalized = normalized_name(software_name)
    if not normalized:
        return

    next_audit_date = calculate_next_audit_date_from_assessment(
        assessment_record.get("assessment_date", ""),
        assessment_record.get("audit_reminder_frequency", ""),
    )
    if not next_audit_date:
        return

    for record in SOFTWARE_RECORDS:
        if normalized_name(record.get("software_name", "")) == normalized and not record.get("is_assessment"):
            record["next_audit_date"] = next_audit_date
            record["review_date"] = next_audit_date
            break


def update_software_details(original_software_name, updated_details):
    original_normalized = normalized_name(original_software_name)

    for record in SOFTWARE_RECORDS:
        if normalized_name(record.get("software_name", "")) == original_normalized:
            for field in SOFTWARE_DETAIL_FIELDS:
                if field in updated_details:
                    record[field] = updated_details[field]
            record["review_date"] = updated_details["next_audit_date"] or calculate_review_date(
                updated_details["deployment_date"],
                updated_details["audit_reminder_frequency"],
            )
            record["assessment_date"] = determine_assessment_date(record)
            enriched_record = enrich_assessment(record)
            record.update(enriched_record)

    vendor_name = updated_details["vendor_name"]
    if vendor_name:
        existing_vendor = get_vendor_by_name(vendor_name)
        if existing_vendor is None:
            VENDOR_RECORDS.append(
                {
                    "vendor_name": vendor_name,
                    "vendor_country": updated_details["vendor_country"],
                    "vendor_website": "",
                }
            )
        else:
            for vendor in VENDOR_RECORDS:
                if normalized_name(vendor["vendor_name"]) == normalized_name(vendor_name):
                    vendor["vendor_country"] = updated_details["vendor_country"]
                    break

    persist_software_records()
    persist_vendor_records()


def save_vendor_terms_from_assessment_form(form):
    if form.get("terms_source", "") != "vendor":
        return
    vendor_name = form.get("vendor_name", "").strip()
    if not vendor_name:
        return
    age = form.get("vendor_age_restrictions_edit", "").strip()
    acceptance = form.get("vendor_allows_acceptance_edit", "").strip()
    notes = form.get("vendor_terms_notes_edit", "").strip()
    if not any([age, acceptance, notes]):
        return
    normalized = normalized_name(vendor_name)
    for vendor in VENDOR_RECORDS:
        if normalized_name(vendor["vendor_name"]) == normalized:
            vendor["vendor_age_restrictions"] = age
            vendor["vendor_allows_acceptance_on_behalf_of_entity"] = acceptance
            vendor["vendor_terms_conditions_notes"] = notes
            break
    else:
        entry = blank_vendor()
        entry["vendor_name"] = vendor_name
        entry["vendor_age_restrictions"] = age
        entry["vendor_allows_acceptance_on_behalf_of_entity"] = acceptance
        entry["vendor_terms_conditions_notes"] = notes
        VENDOR_RECORDS.append(entry)
    persist_vendor_records()


def collect_assessment_form_data(form, assessment_id=None):
    record = {"id": assessment_id} if assessment_id is not None else {}
    for field in ASSESSMENT_FIELDS:
        if field in CHECKBOX_FIELDS:
            values = [str(value).strip().lower() for value in form.getlist(field)]
            record[field] = any(value in {"on", "true", "1", "yes"} for value in values)
        elif field == "license_cost":
            record[field] = normalize_license_cost(form.get(field, ""))
        else:
            record[field] = form.get(field, "").strip()

    if record.get("license_type") == "Free":
        record["free_software"] = True
        record["currency_type"] = ""
        record["license_cost"] = ""
        record["subscription_billing_frequency"] = ""
    elif record.get("free_software"):
        record["currency_type"] = ""
        record["license_cost"] = ""
    if record.get("license_type") == "Perpetual":
        record["license_renewal_date"] = ""
    if record.get("license_type") not in ("Subscription",):
        record["subscription_billing_frequency"] = ""

    record["vendor_terms_conditions_link"] = form.get("vendor_terms_conditions_link", "").strip()
    record["vendor_privacy_policy_link"] = form.get("vendor_privacy_policy_link", "").strip()

    linked_software = get_latest_software_record(record.get("software_name", ""))
    if linked_software is not None:
        for field in (
            "vendor_name",
            "software_description",
            "vendor_country",
            "vendor_website",
            "software_website",
            "terms_conditions_link",
            "license_agreement_link",
            "license_type",
            "purchase_link",
            "license_start_date",
            "license_renewal_date",
            "deployment_groups",
            "deployment_date",
            "audit_reminder_frequency",
            "vendor_security_assessment",
        ):
            if not record.get(field):
                record[field] = linked_software.get(field, "")

    record["software_id"] = record.get("software_id") or find_software_id(record.get("software_name", ""))
    record["assessment_date"] = ""
    return enrich_assessment(record)


def collect_vendor_form_data(form):
    vendor_audit_reminder_frequency = form.get("vendor_audit_reminder_frequency", "").strip() or "1_year"
    vendor_next_audit_date = form.get("vendor_next_audit_date", "").strip()
    no_vendor_terms_conditions = "no_vendor_terms_conditions" in form
    return {
        "vendor_name": form.get("vendor_name", "").strip(),
        "vendor_country": form.get("vendor_country", "").strip(),
        "vendor_website": form.get("vendor_website", "").strip(),
        "vendor_terms_conditions_link": form.get("vendor_terms_conditions_link", "").strip(),
        "no_vendor_terms_conditions": no_vendor_terms_conditions,
        "vendor_cookie_policy_link": form.get("vendor_cookie_policy_link", "").strip(),
        "vendor_privacy_policy_link": form.get("vendor_privacy_policy_link", "").strip(),
        "online_support": form.get("online_support", "").strip(),
        "vendor_audit_reminder_frequency": vendor_audit_reminder_frequency,
        "vendor_next_audit_date": vendor_next_audit_date,
        "vendor_age_restrictions": "" if no_vendor_terms_conditions else form.get("vendor_age_restrictions", "").strip(),
        "vendor_terms_conditions_notes": "" if no_vendor_terms_conditions else form.get("vendor_terms_conditions_notes", "").strip(),
        "vendor_allows_acceptance_on_behalf_of_entity": "" if no_vendor_terms_conditions else form.get("vendor_allows_acceptance_on_behalf_of_entity", "").strip(),
    }


def blank_vendor():
    return {
        "vendor_name": "",
        "vendor_country": "",
        "vendor_website": "",
        "vendor_terms_conditions_link": "",
        "no_vendor_terms_conditions": False,
        "vendor_cookie_policy_link": "",
        "vendor_privacy_policy_link": "",
        "online_support": "",
        "vendor_audit_reminder_frequency": "1_year",
        "vendor_next_audit_date": "",
        "vendor_age_restrictions": "",
        "vendor_terms_conditions_notes": "",
        "vendor_allows_acceptance_on_behalf_of_entity": "",
        "privacy_policy_pdf_filename": "",
        "privacy_policy_pdf_original_name": "",
        "vendor_tc_pdf_filename": "",
        "vendor_tc_pdf_original_name": "",
    }


def build_vendor_context(vendor_name):
    vendor = get_vendor_record_or_none(vendor_name)
    if vendor is not None:
        return vendor

    vendor = blank_vendor()
    vendor["vendor_name"] = vendor_name.strip()
    return vendor


def collect_vendor_assessment_form_data(form, assessment_id=None):
    assessment = {"id": assessment_id} if assessment_id is not None else {}
    assessment["vendor_name"] = form.get("vendor_name", "").strip()
    existing_assessment = get_vendor_assessment_or_none(assessment_id) if assessment_id is not None else None
    submit_action = form.get("submit_action", "submit")
    vendor = get_vendor_record_or_none(assessment["vendor_name"]) or {}
    assessment["vendor_assessment_date"] = (
        date.today().isoformat()
        if submit_action == "submit"
        else (existing_assessment or {}).get("vendor_assessment_date", "") or date.today().isoformat()
    )
    assessment["vendor_security_assessment"] = form.get("vendor_security_assessment", "").strip()
    assessment["cloud_hosted_data"] = form.get("cloud_hosted_data", "").strip()
    if assessment["cloud_hosted_data"] == "Yes":
        assessment["data_storage_location"] = normalize_data_storage_locations(form.getlist("data_storage_location"))
        home = get_home_country()
        non_home = [loc for loc in get_selected_values(assessment["data_storage_location"]) if loc != home]
        assessment["dpa_status"] = form.get("dpa_status", "").strip() if non_home else ""
    else:
        assessment["dpa_status"] = ""
        assessment["data_storage_location"] = ""
    assessment["storage_location_notes"] = (
        form.get("storage_location_notes", "").strip()
        if assessment["cloud_hosted_data"] == "Yes"
        else ""
    )
    assessment["data_types_stored"] = (
        normalize_data_types_stored(form.getlist("data_types_stored"))
        if assessment["cloud_hosted_data"] == "Yes"
        else ""
    )
    assessment["privacy_laws_adhered_to"] = normalize_privacy_laws_adhered_to(form.getlist("privacy_laws_adhered_to"))
    assessment["privacy_law_notes"] = form.get("privacy_law_notes", "").strip()
    assessment["security_privacy_standards"] = normalize_security_privacy_standards(form.getlist("security_privacy_standards"))
    assessment["sector_specific_contextual_laws"] = normalize_sector_specific_contextual_laws(form.getlist("sector_specific_contextual_laws"))
    assessment["cross_border_data_transfer_mechanisms"] = normalize_cross_border_data_transfer_mechanisms(form.getlist("cross_border_data_transfer_mechanisms"))
    assessment["us_specific_laws"] = normalize_us_specific_laws(form.getlist("us_specific_laws"))
    assessment["data_storage_notes"] = (
        form.get("data_storage_notes", "").strip()
        if assessment["cloud_hosted_data"] in {"Yes", "No"}
        else ""
    )
    assessment["privacy_notes"] = form.get("privacy_notes", "").strip()
    assessment["no_vendor_privacy_policy"] = "no_vendor_privacy_policy" in form
    if assessment["no_vendor_privacy_policy"]:
        assessment["cloud_hosted_data"] = ""
        assessment["data_storage_location"] = ""
        assessment["dpa_status"] = ""
        assessment["storage_location_notes"] = ""
        assessment["data_types_stored"] = ""
        assessment["data_storage_notes"] = ""
        assessment["privacy_laws_adhered_to"] = ""
        assessment["privacy_law_notes"] = ""
        assessment["sector_specific_contextual_laws"] = ""
        assessment["cross_border_data_transfer_mechanisms"] = ""
        assessment["us_specific_laws"] = ""
        assessment["security_privacy_standards"] = ""
        assessment["privacy_notes"] = ""
    assessment["vendor_audit_reminder_frequency"] = vendor.get("vendor_audit_reminder_frequency", "") or "1_year"
    assessment["vendor_next_audit_date"] = calculate_next_audit_date_from_assessment(
        assessment["vendor_assessment_date"],
        assessment["vendor_audit_reminder_frequency"],
    )
    assessment["submission_status"] = "draft" if submit_action == "draft" else "submitted"
    assessment["submitted_date"] = assessment["vendor_assessment_date"] if assessment["submission_status"] == "submitted" else ""
    return enrich_vendor_assessment(assessment)


def get_vendor_record_or_none(vendor_name):
    normalized = normalized_name(vendor_name)
    if not normalized:
        return None

    for vendor in build_vendor_list():
        if normalized_name(vendor["vendor_name"]) == normalized:
            return vendor
    return None


def get_vendor_linked_software(vendor_name):
    normalized = normalized_name(vendor_name)
    if not normalized:
        return []

    linked_software = [
        record for record in build_software_catalog()
        if normalized_name(record.get("vendor_name", "")) == normalized
    ]
    return sorted(
        linked_software,
        key=lambda record: normalized_name(record.get("software_name", "")),
    )


def get_vendor_assessment_or_none(assessment_id):
    for record in VENDOR_ASSESSMENT_RECORDS:
        if record["id"] == assessment_id:
            return record
    return None


def get_vendor_assessments(vendor_name):
    normalized = normalized_name(vendor_name)
    if not normalized:
        return []

    records = [
        record for record in VENDOR_ASSESSMENT_RECORDS
        if normalized_name(record.get("vendor_name", "")) == normalized
    ]
    return sorted(
        records,
        key=lambda record: (record.get("vendor_assessment_date", ""), record.get("submitted_date", ""), record.get("id", 0)),
        reverse=True,
    )


def get_latest_vendor_assessment(vendor_name):
    assessments = get_vendor_assessments(vendor_name)
    return assessments[0] if assessments else None


def get_latest_submitted_vendor_assessment(vendor_name):
    for assessment in get_vendor_assessments(vendor_name):
        if is_submitted_vendor_assessment(assessment):
            return assessment
    return None


def sync_vendor_schedule_from_assessment(assessment):
    if assessment.get("submission_status") == "draft":
        return

    vendor_name = assessment.get("vendor_name", "").strip()
    next_audit_date = calculate_next_audit_date_from_assessment(
        assessment.get("vendor_assessment_date", ""),
        assessment.get("vendor_audit_reminder_frequency", ""),
    )
    if not vendor_name or not next_audit_date:
        return

    updated_vendor = build_vendor_context(vendor_name)
    updated_vendor["vendor_audit_reminder_frequency"] = updated_vendor.get("vendor_audit_reminder_frequency", "") or "1_year"
    updated_vendor["vendor_next_audit_date"] = next_audit_date
    update_vendor_details(vendor_name, updated_vendor)


def update_vendor_details(original_name, updated_vendor):
    original_normalized = normalized_name(original_name)
    updated_name = updated_vendor["vendor_name"].strip()

    for record in SOFTWARE_RECORDS:
        if normalized_name(record["vendor_name"]) == original_normalized:
            record["vendor_name"] = updated_name
            record["vendor_country"] = updated_vendor["vendor_country"]
            record["vendor_website"] = updated_vendor["vendor_website"]
            record["vendor_terms_conditions_link"] = updated_vendor["vendor_terms_conditions_link"]
            record["vendor_privacy_policy_link"] = updated_vendor["vendor_privacy_policy_link"]
            record["online_support"] = updated_vendor["online_support"]
            record["vendor_audit_reminder_frequency"] = updated_vendor["vendor_audit_reminder_frequency"]
            record["vendor_next_audit_date"] = updated_vendor["vendor_next_audit_date"]

    for assessment in VENDOR_ASSESSMENT_RECORDS:
        if normalized_name(assessment.get("vendor_name", "")) == original_normalized:
            assessment["vendor_name"] = updated_name

    updated_manual_vendor = False
    for vendor in VENDOR_RECORDS:
        if normalized_name(vendor["vendor_name"]) == original_normalized:
            vendor.update(updated_vendor)
            updated_manual_vendor = True

    if not updated_manual_vendor:
        VENDOR_RECORDS.append(dict(updated_vendor))

    persist_software_records()
    persist_vendor_records()
    persist_vendor_assessment_records()


def delete_vendor_details(vendor_name):
    normalized = normalized_name(vendor_name)
    if not normalized:
        return

    for record in SOFTWARE_RECORDS:
        if normalized_name(record.get("vendor_name", "")) == normalized:
            record["vendor_name"] = ""
            record["vendor_country"] = ""
            record["vendor_website"] = ""
            record["vendor_terms_conditions_link"] = ""
            record["vendor_privacy_policy_link"] = ""
            record["online_support"] = ""
            record["vendor_audit_reminder_frequency"] = ""
            record["vendor_next_audit_date"] = ""

    VENDOR_RECORDS[:] = [
        vendor for vendor in VENDOR_RECORDS
        if normalized_name(vendor.get("vendor_name", "")) != normalized
    ]
    VENDOR_ASSESSMENT_RECORDS[:] = [
        assessment for assessment in VENDOR_ASSESSMENT_RECORDS
        if normalized_name(assessment.get("vendor_name", "")) != normalized
    ]

    persist_software_records()
    persist_vendor_records()
    persist_vendor_assessment_records()


def get_vendor_by_name(vendor_name):
    normalized = normalized_name(vendor_name)
    if not normalized:
        return None

    for vendor in build_vendor_list():
        if normalized_name(vendor["vendor_name"]) == normalized:
            return vendor
    return None


def get_vendor_terms_link_for_record(record):
    vendor = get_vendor_by_name(record.get("vendor_name", ""))
    if vendor is None:
        return ""
    return vendor.get("vendor_terms_conditions_link", "")


def get_vendor_privacy_policy_link_for_record(record):
    vendor = get_vendor_by_name(record.get("vendor_name", ""))
    if vendor is None:
        return ""
    return vendor.get("vendor_privacy_policy_link", "")


def get_vendor_age_restrictions_for_record(record):
    vendor = get_vendor_by_name(record.get("vendor_name", ""))
    return (vendor or {}).get("vendor_age_restrictions", "")


def get_vendor_terms_conditions_notes_for_record(record):
    vendor = get_vendor_by_name(record.get("vendor_name", ""))
    return (vendor or {}).get("vendor_terms_conditions_notes", "")


def get_vendor_allows_acceptance_for_record(record):
    vendor = get_vendor_by_name(record.get("vendor_name", ""))
    return (vendor or {}).get("vendor_allows_acceptance_on_behalf_of_entity", "")


def get_software_item_by_name(software_name):
    normalized = normalized_name(software_name)
    if not normalized:
        return None

    for software in SOFTWARE_ITEMS:
        if normalized_name(software.get("software_name", "")) == normalized:
            return software
    return None


def get_software_purchase_link_for_record(record):
    software = get_software_item_by_name(record.get("software_name", ""))
    if software is None:
        return record.get("purchase_link", "")
    return software.get("purchase_link", "") or record.get("purchase_link", "")


def save_software_purchase_link(software_name, purchase_link):
    normalized = normalized_name(software_name)
    cleaned_link = purchase_link.strip()
    if not normalized:
        return False

    updated = False
    for record in SOFTWARE_RECORDS:
        if normalized_name(record.get("software_name", "")) == normalized:
            record["purchase_link"] = cleaned_link
            updated = True

    for record in SOFTWARE_ITEMS:
        if normalized_name(record.get("software_name", "")) == normalized:
            record["purchase_link"] = cleaned_link
            updated = True

    if not updated:
        source_record = get_latest_software_record(software_name)
        software_id = ensure_software_item_for_record(
            source_record or {"software_name": software_name, "purchase_link": cleaned_link}
        )
        for record in SOFTWARE_ITEMS:
            if record.get("id") == software_id:
                record["purchase_link"] = cleaned_link
                if record not in SOFTWARE_RECORDS:
                    SOFTWARE_RECORDS.append(record)
                updated = True
                break

    persist_software_records()
    return updated


def save_software_website(software_name, software_website):
    normalized = normalized_name(software_name)
    cleaned_link = software_website.strip()
    if not normalized:
        return False

    updated = False
    for record in SOFTWARE_RECORDS:
        if normalized_name(record.get("software_name", "")) == normalized:
            record["software_website"] = cleaned_link
            updated = True

    for record in SOFTWARE_ITEMS:
        if normalized_name(record.get("software_name", "")) == normalized:
            record["software_website"] = cleaned_link
            updated = True

    if not updated:
        source_record = get_latest_software_record(software_name)
        software_id = ensure_software_item_for_record(
            source_record or {"software_name": software_name, "software_website": cleaned_link}
        )
        for record in SOFTWARE_ITEMS:
            if record.get("id") == software_id:
                record["software_website"] = cleaned_link
                if record not in SOFTWARE_RECORDS:
                    SOFTWARE_RECORDS.append(record)
                updated = True
                break

    persist_software_records()
    return updated


def save_software_license_agreement_link(software_name, license_agreement_link):
    normalized = normalized_name(software_name)
    cleaned_link = license_agreement_link.strip()
    if not normalized:
        return False

    updated = False
    for record in SOFTWARE_RECORDS:
        if normalized_name(record.get("software_name", "")) == normalized:
            record["license_agreement_link"] = cleaned_link
            updated = True

    for record in SOFTWARE_ITEMS:
        if normalized_name(record.get("software_name", "")) == normalized:
            record["license_agreement_link"] = cleaned_link
            updated = True

    if not updated:
        source_record = get_latest_software_record(software_name)
        software_id = ensure_software_item_for_record(
            source_record or {"software_name": software_name, "license_agreement_link": cleaned_link}
        )
        for record in SOFTWARE_ITEMS:
            if record.get("id") == software_id:
                record["license_agreement_link"] = cleaned_link
                if record not in SOFTWARE_RECORDS:
                    SOFTWARE_RECORDS.append(record)
                updated = True
                break

    persist_software_records()
    return updated


def save_software_terms_conditions_link(software_name, terms_conditions_link):
    normalized = normalized_name(software_name)
    cleaned_link = terms_conditions_link.strip()
    if not normalized:
        return False

    updated = False
    for record in SOFTWARE_RECORDS:
        if normalized_name(record.get("software_name", "")) == normalized:
            record["terms_conditions_link"] = cleaned_link
            updated = True

    for record in SOFTWARE_ITEMS:
        if normalized_name(record.get("software_name", "")) == normalized:
            record["terms_conditions_link"] = cleaned_link
            updated = True

    if not updated:
        source_record = get_latest_software_record(software_name)
        software_id = ensure_software_item_for_record(
            source_record or {"software_name": software_name, "terms_conditions_link": cleaned_link}
        )
        for record in SOFTWARE_ITEMS:
            if record.get("id") == software_id:
                record["terms_conditions_link"] = cleaned_link
                if record not in SOFTWARE_RECORDS:
                    SOFTWARE_RECORDS.append(record)
                updated = True
                break

    persist_software_records()
    return updated


def save_vendor_terms_conditions_link(vendor_name, terms_conditions_link):
    normalized = normalized_name(vendor_name)
    cleaned_link = terms_conditions_link.strip()
    if not normalized:
        return False

    for record in SOFTWARE_RECORDS:
        if normalized_name(record.get("vendor_name", "")) == normalized:
            record["vendor_terms_conditions_link"] = cleaned_link

    updated_manual_vendor = False
    for vendor in VENDOR_RECORDS:
        if normalized_name(vendor.get("vendor_name", "")) == normalized:
            vendor["vendor_terms_conditions_link"] = cleaned_link
            updated_manual_vendor = True

    if not updated_manual_vendor:
        existing_vendor = get_vendor_by_name(vendor_name)
        if existing_vendor is not None:
            VENDOR_RECORDS.append(
                {
                    "vendor_name": existing_vendor.get("vendor_name", vendor_name).strip(),
                    "vendor_country": existing_vendor.get("vendor_country", ""),
                    "vendor_website": existing_vendor.get("vendor_website", ""),
                    "vendor_terms_conditions_link": cleaned_link,
                    "vendor_cookie_policy_link": existing_vendor.get("vendor_cookie_policy_link", ""),
                    "vendor_privacy_policy_link": existing_vendor.get("vendor_privacy_policy_link", ""),
                    "online_support": existing_vendor.get("online_support", ""),
                }
            )

    persist_software_records()
    persist_vendor_records()
    return True


def save_vendor_cookie_policy_link(vendor_name, cookie_policy_link):
    normalized = normalized_name(vendor_name)
    cleaned_link = cookie_policy_link.strip()
    if not normalized:
        return False

    updated_manual_vendor = False
    for vendor in VENDOR_RECORDS:
        if normalized_name(vendor.get("vendor_name", "")) == normalized:
            vendor["vendor_cookie_policy_link"] = cleaned_link
            updated_manual_vendor = True

    if not updated_manual_vendor:
        existing_vendor = get_vendor_by_name(vendor_name)
        if existing_vendor is not None:
            VENDOR_RECORDS.append(
                {
                    "vendor_name": existing_vendor.get("vendor_name", vendor_name).strip(),
                    "vendor_country": existing_vendor.get("vendor_country", ""),
                    "vendor_website": existing_vendor.get("vendor_website", ""),
                    "vendor_terms_conditions_link": existing_vendor.get("vendor_terms_conditions_link", ""),
                    "vendor_cookie_policy_link": cleaned_link,
                    "vendor_privacy_policy_link": existing_vendor.get("vendor_privacy_policy_link", ""),
                    "online_support": existing_vendor.get("online_support", ""),
                }
            )

    persist_vendor_records()
    return True


def save_vendor_website_link(vendor_name, website_link):
    normalized = normalized_name(vendor_name)
    cleaned_link = website_link.strip()
    if not normalized:
        return False

    for record in SOFTWARE_RECORDS:
        if normalized_name(record.get("vendor_name", "")) == normalized:
            record["vendor_website"] = cleaned_link

    updated_manual_vendor = False
    for vendor in VENDOR_RECORDS:
        if normalized_name(vendor.get("vendor_name", "")) == normalized:
            vendor["vendor_website"] = cleaned_link
            updated_manual_vendor = True

    if not updated_manual_vendor:
        existing_vendor = get_vendor_by_name(vendor_name)
        if existing_vendor is not None:
            VENDOR_RECORDS.append(
                {
                    "vendor_name": existing_vendor.get("vendor_name", vendor_name).strip(),
                    "vendor_country": existing_vendor.get("vendor_country", ""),
                    "vendor_website": cleaned_link,
                    "vendor_terms_conditions_link": existing_vendor.get("vendor_terms_conditions_link", ""),
                    "vendor_privacy_policy_link": existing_vendor.get("vendor_privacy_policy_link", ""),
                    "online_support": existing_vendor.get("online_support", ""),
                }
            )

    persist_software_records()
    persist_vendor_records()
    return True


def save_vendor_privacy_policy_link(vendor_name, privacy_policy_link):
    normalized = normalized_name(vendor_name)
    cleaned_link = privacy_policy_link.strip()
    if not normalized:
        return False

    for record in SOFTWARE_RECORDS:
        if normalized_name(record.get("vendor_name", "")) == normalized:
            record["vendor_privacy_policy_link"] = cleaned_link

    updated_manual_vendor = False
    for vendor in VENDOR_RECORDS:
        if normalized_name(vendor.get("vendor_name", "")) == normalized:
            vendor["vendor_privacy_policy_link"] = cleaned_link
            updated_manual_vendor = True

    if not updated_manual_vendor:
        existing_vendor = get_vendor_by_name(vendor_name)
        if existing_vendor is not None:
            VENDOR_RECORDS.append(
                {
                    "vendor_name": existing_vendor.get("vendor_name", vendor_name).strip(),
                    "vendor_country": existing_vendor.get("vendor_country", ""),
                    "vendor_website": existing_vendor.get("vendor_website", ""),
                    "vendor_terms_conditions_link": existing_vendor.get("vendor_terms_conditions_link", ""),
                    "vendor_cookie_policy_link": existing_vendor.get("vendor_cookie_policy_link", ""),
                    "vendor_privacy_policy_link": cleaned_link,
                    "online_support": existing_vendor.get("online_support", ""),
                }
            )

    persist_software_records()
    persist_vendor_records()
    return True


def save_vendor_online_support_link(vendor_name, support_link):
    normalized = normalized_name(vendor_name)
    cleaned_link = support_link.strip()
    if not normalized:
        return False

    for record in SOFTWARE_RECORDS:
        if normalized_name(record.get("vendor_name", "")) == normalized:
            record["online_support"] = cleaned_link

    updated_manual_vendor = False
    for vendor in VENDOR_RECORDS:
        if normalized_name(vendor.get("vendor_name", "")) == normalized:
            vendor["online_support"] = cleaned_link
            updated_manual_vendor = True

    if not updated_manual_vendor:
        existing_vendor = get_vendor_by_name(vendor_name)
        if existing_vendor is not None:
            VENDOR_RECORDS.append(
                {
                    "vendor_name": existing_vendor.get("vendor_name", vendor_name).strip(),
                    "vendor_country": existing_vendor.get("vendor_country", ""),
                    "vendor_website": existing_vendor.get("vendor_website", ""),
                    "vendor_terms_conditions_link": existing_vendor.get("vendor_terms_conditions_link", ""),
                    "vendor_privacy_policy_link": existing_vendor.get("vendor_privacy_policy_link", ""),
                    "online_support": cleaned_link,
                }
            )

    persist_software_records()
    persist_vendor_records()
    return True


def sync_vendor_from_assessment(record):
    vendor_name = record.get("vendor_name", "").strip()
    if not vendor_name:
        return

    existing_vendor = get_vendor_by_name(vendor_name)
    if existing_vendor is None:
        VENDOR_RECORDS.append(
            {
                "vendor_name": vendor_name,
                "vendor_country": record.get("vendor_country", "").strip(),
                "vendor_website": record.get("vendor_website", "").strip(),
                "vendor_terms_conditions_link": record.get("vendor_terms_conditions_link", "").strip(),
                "vendor_privacy_policy_link": record.get("vendor_privacy_policy_link", "").strip(),
                "online_support": record.get("online_support", "").strip(),
            }
        )
        return

    for vendor in VENDOR_RECORDS:
        if normalized_name(vendor["vendor_name"]) == normalized_name(vendor_name):
            if not vendor["vendor_country"] and record.get("vendor_country"):
                vendor["vendor_country"] = record["vendor_country"].strip()
            if not vendor.get("vendor_website") and record.get("vendor_website"):
                vendor["vendor_website"] = record["vendor_website"].strip()
            if not vendor.get("vendor_terms_conditions_link") and record.get("vendor_terms_conditions_link"):
                vendor["vendor_terms_conditions_link"] = record["vendor_terms_conditions_link"].strip()
            if not vendor.get("vendor_privacy_policy_link") and record.get("vendor_privacy_policy_link"):
                vendor["vendor_privacy_policy_link"] = record["vendor_privacy_policy_link"].strip()
            if not vendor.get("online_support") and record.get("online_support"):
                vendor["online_support"] = record["online_support"].strip()
            return


def build_dashboard_context(show_all_upcoming_audits=False):
    software_catalog = build_software_catalog(active_only=True)
    risk_counts = Counter()
    for _rc_record in software_catalog:
        _rc_risk = normalize_risk_level(_rc_record.get("risk_level") or "")
        risk_counts[_rc_risk if _rc_risk in RISK_CATEGORY_OPTIONS else "Not Assigned"] += 1
    today = date.today()
    draft_assessments = sorted(
        [
            record for record in SOFTWARE_RECORDS
            if record.get("is_assessment") and record.get("submission_status") == "draft"
        ],
        key=lambda record: (record.get("assessment_date", ""), record.get("id", 0)),
        reverse=True,
    )
    draft_assessment_items = []
    for record in draft_assessments:
        draft_item = dict(record)
        try:
            assessment_date = datetime.strptime(record.get("assessment_date", ""), "%Y-%m-%d").date()
        except ValueError:
            assessment_date = None

        draft_item["is_overdue"] = bool(assessment_date and assessment_date < today)
        draft_item["overdue_label"] = (
            f"Overdue by {describe_overdue_duration((today - assessment_date).days)}"
            if assessment_date and assessment_date < today
            else ""
        )
        draft_assessment_items.append(draft_item)

    upcoming_audit_candidates = []
    for record in software_catalog:
        if is_submitted_assessment(record) and (record.get("next_audit_date") or record.get("review_date")):
            upcoming_audit_candidates.append(("software", record.get("next_audit_date") or record.get("review_date", ""), record))

    for vendor in build_vendor_list(active_only=True):
        if vendor.get("vendor_next_audit_date"):
            vendor_record = dict(vendor)
            vendor_record["vendor_assessment_date"] = ""
            vendor_record["vendor_next_audit_date"] = vendor.get("vendor_next_audit_date", "")
            upcoming_audit_candidates.append(("vendor", vendor.get("vendor_next_audit_date", ""), vendor_record))

    upcoming_audits = sorted(upcoming_audit_candidates, key=lambda item: item[1])
    display_limit = None if show_all_upcoming_audits else 8
    upcoming_audit_items = []
    for audit_type, audit_date_value, record in upcoming_audits:
        audit_item = dict(record)
        try:
            review_date = datetime.strptime(audit_date_value, "%Y-%m-%d").date()
        except ValueError:
            review_date = None
        audit_item["is_overdue"] = bool(review_date and review_date < today)
        audit_item["overdue_label"] = (
            f"Overdue by {describe_overdue_duration((today - review_date).days)}"
            if review_date and review_date < today
            else ""
        )
        audit_item["audit_type"] = audit_type
        audit_item["audit_date"] = audit_date_value
        upcoming_audit_items.append(audit_item)

    software_needing_assessment = [
        record for record in software_catalog
        if not get_software_history(record.get("software_name", ""))
        and normalized_name(record.get("software_name", "")) not in {
            normalized_name(draft.get("software_name", ""))
            for draft in draft_assessments
        }
    ]

    vendor_names_with_assessments = {
        normalized_name(assessment.get("vendor_name", ""))
        for assessment in VENDOR_ASSESSMENT_RECORDS
        if assessment.get("vendor_name", "").strip()
    }
    vendor_names_with_drafts = {
        normalized_name(assessment.get("vendor_name", ""))
        for assessment in VENDOR_ASSESSMENT_RECORDS
        if assessment.get("submission_status") == "draft" and assessment.get("vendor_name", "").strip()
    }
    vendors_needing_assessment = [
        vendor for vendor in build_vendor_list(active_only=True)
        if normalized_name(vendor.get("vendor_name", "")) not in vendor_names_with_assessments
        and normalized_name(vendor.get("vendor_name", "")) not in vendor_names_with_drafts
    ]

    vendor_draft_assessment_items = []
    for record in sorted(
        [
            assessment for assessment in VENDOR_ASSESSMENT_RECORDS
            if assessment.get("submission_status") == "draft"
        ],
        key=lambda assessment: (assessment.get("vendor_assessment_date", ""), assessment.get("id", 0)),
        reverse=True,
    ):
        draft_item = dict(record)
        try:
            assessment_date = datetime.strptime(record.get("vendor_assessment_date", ""), "%Y-%m-%d").date()
        except ValueError:
            assessment_date = None

        draft_item["is_overdue"] = bool(assessment_date and assessment_date < today)
        draft_item["overdue_label"] = (
            f"Overdue by {describe_overdue_duration((today - assessment_date).days)}"
            if assessment_date and assessment_date < today
            else ""
        )
        vendor_draft_assessment_items.append(draft_item)

    upcoming_software_audits = [item for item in upcoming_audit_items if item.get("audit_type") == "software"]
    upcoming_vendor_audits = [item for item in upcoming_audit_items if item.get("audit_type") == "vendor"]
    if display_limit is not None:
        upcoming_software_audits = upcoming_software_audits[:display_limit]
        upcoming_vendor_audits = upcoming_vendor_audits[:display_limit]

    return {
        "software_records": software_catalog,
        "vendors": build_vendor_list(active_only=True),
        "draft_assessments": draft_assessment_items,
        "draft_vendor_assessments": vendor_draft_assessment_items,
        "upcoming_audits": upcoming_audit_items if display_limit is None else upcoming_audit_items[:display_limit],
        "upcoming_software_audits": upcoming_software_audits,
        "upcoming_vendor_audits": upcoming_vendor_audits,
        "show_all_upcoming_audits": show_all_upcoming_audits,
        "has_more_upcoming_audits": len(upcoming_audits) > 8,
        "software_needing_assessment": software_needing_assessment,
        "vendors_needing_assessment": vendors_needing_assessment,
        "dashboard_stats": {
            "total_products": len(software_catalog),
            "total_vendors": len({record["vendor_name"] for record in software_catalog if record.get("vendor_name")}),
        },
        "risk_counts": dict(risk_counts),
    }


def build_overseas_hosting_report():
    overseas_records = [
        record for record in SOFTWARE_RECORDS
        if is_submitted_assessment(record)
        and record.get("deployed")
        and any(
            location != "Australia"
            for location in get_selected_values((get_latest_vendor_assessment(record.get("vendor_name", "")) or {}).get("data_storage_location", ""))
        )
    ]
    return sorted(
        overseas_records,
        key=lambda record: (record.get("assessment_date", ""), normalized_name(record.get("software_name", ""))),
        reverse=True,
    )


def build_data_hosting_heatmap():
    location_counts = Counter()
    location_vendors = defaultdict(list)
    vendor_count = 0
    country_risk_assignments = get_country_risk_assignments()

    for vendor in build_vendor_list(active_only=True):
        vendor_assessment = get_latest_vendor_assessment(vendor.get("vendor_name", ""))
        locations = set(get_selected_values((vendor_assessment or {}).get("data_storage_location", "")))
        if not locations:
            continue

        vendor_count += 1
        location_counts.update(locations)
        for location in locations:
            location_vendors[location].append(
                {
                    "vendor_name": vendor.get("vendor_name", ""),
                    "vendor_assessment_date": vendor_assessment.get("vendor_assessment_date", ""),
                }
            )

    max_count = max(location_counts.values(), default=0)
    total_location_count = sum(location_counts.values())
    heatmap_locations = []
    for location, count in sorted(location_counts.items(), key=lambda item: (-item[1], item[0])):
        intensity = max(1, min(5, round((count / max_count) * 5))) if max_count else 0
        location_item = {
            "location": location,
            "count": count,
            "intensity": intensity,
            "percentage": round((count / total_location_count) * 100) if total_location_count else 0,
            "risk_level": country_risk_assignments.get(location, ""),
            "marker_color": RISK_CATEGORY_MAP_COLORS.get(country_risk_assignments.get(location, ""), DEFAULT_MAP_RISK_COLOR),
            "vendors": sorted(
                location_vendors.get(location, []),
                key=lambda vendor: normalized_name(vendor.get("vendor_name", "")),
            ),
        }
        coordinates = COUNTRY_MAP_COORDINATES.get(location)
        if coordinates is not None:
            latitude, longitude = coordinates
            location_item["latitude"] = latitude
            location_item["longitude"] = longitude
            location_item["map_x"] = round(((longitude + 180) / 360) * 1000, 1)
            location_item["map_y"] = round(((90 - latitude) / 180) * 500, 1)
            location_item["marker_radius"] = 8 + (intensity * 3)
        heatmap_locations.append(location_item)

    mapped_locations = [item for item in heatmap_locations if "map_x" in item]

    return {
        "locations": heatmap_locations,
        "map_locations": mapped_locations,
        "max_count": max_count,
        "assessment_count": vendor_count,
        "vendor_count": vendor_count,
        "total_locations": len(heatmap_locations),
        "total_location_count": total_location_count,
        "mapped_locations": len(mapped_locations),
    }


def build_vendor_origin_map():
    location_counts = Counter()
    location_vendors = defaultdict(list)

    for vendor in build_vendor_list(active_only=True):
        country = vendor.get("vendor_country", "").strip()
        if not country:
            continue
        location_counts[country] += 1
        location_vendors[country].append({"vendor_name": vendor.get("vendor_name", "")})

    total_count = sum(location_counts.values())
    origin_locations = []

    for location, count in sorted(location_counts.items(), key=lambda item: (-item[1], item[0])):
        location_item = {
            "location": location,
            "count": count,
            "percentage": round((count / total_count) * 100) if total_count else 0,
            "vendors": sorted(
                location_vendors.get(location, []),
                key=lambda v: normalized_name(v.get("vendor_name", "")),
            ),
        }
        coordinates = COUNTRY_MAP_COORDINATES.get(location)
        if coordinates is not None:
            latitude, longitude = coordinates
            location_item["latitude"] = latitude
            location_item["longitude"] = longitude
        origin_locations.append(location_item)

    mapped_locations = [item for item in origin_locations if "latitude" in item]

    return {
        "locations": origin_locations,
        "map_locations": mapped_locations,
        "vendor_count": total_count,
    }


def build_vendors_without_hosting_locations_report():
    vendors_without_locations = []

    for vendor in build_vendor_list(active_only=True):
        latest_assessment = get_latest_submitted_vendor_assessment(vendor.get("vendor_name", ""))
        if latest_assessment is None:
            continue

        locations = get_selected_values(latest_assessment.get("data_storage_location", ""))
        if locations:
            continue

        if latest_assessment.get("cloud_hosted_data") == "No":
            continue

        reason = "No listed storage countries"

        vendors_without_locations.append(
            {
                "vendor_name": vendor.get("vendor_name", ""),
                "vendor_country": vendor.get("vendor_country", ""),
                "vendor_assessment_date": latest_assessment.get("vendor_assessment_date", ""),
                "reason": reason,
            }
        )

    return sorted(
        vendors_without_locations,
        key=lambda item: (
            item.get("vendor_assessment_date", ""),
            normalized_name(item.get("vendor_name", "")),
        ),
        reverse=True,
    )


def build_vendors_with_unspecified_hosting_locations_report():
    vendors_with_unspecified_locations = []

    for vendor in build_vendor_list(active_only=True):
        latest_assessment = get_latest_vendor_assessment(vendor.get("vendor_name", ""))
        if latest_assessment is None:
            continue

        locations = get_selected_values(latest_assessment.get("data_storage_location", ""))
        if OTHER_DATA_STORAGE_LOCATION not in locations:
            continue

        listed_countries = sorted(location for location in locations if location != OTHER_DATA_STORAGE_LOCATION)
        vendors_with_unspecified_locations.append(
            {
                "vendor_name": vendor.get("vendor_name", ""),
                "vendor_country": vendor.get("vendor_country", ""),
                "vendor_assessment_date": latest_assessment.get("vendor_assessment_date", ""),
                "listed_countries": ", ".join(listed_countries),
            }
        )

    return sorted(
        vendors_with_unspecified_locations,
        key=lambda item: (
            item.get("vendor_assessment_date", ""),
            normalized_name(item.get("vendor_name", "")),
        ),
        reverse=True,
    )


def build_vendor_data_storage_map(vendor_name):
    latest_assessment = get_latest_submitted_vendor_assessment(vendor_name)
    if latest_assessment is None:
        return {
            "has_audit": False,
            "has_locations": False,
            "locations": [],
            "map_locations": [],
            "high_risk_locations": [],
            "vendor_assessment_date": "",
            "no_privacy_policy": False,
        }

    locations = sorted(set(get_selected_values(latest_assessment.get("data_storage_location", ""))))
    map_locations = []
    country_risk_assignments = get_country_risk_assignments()
    for location in locations:
        coordinates = COUNTRY_MAP_COORDINATES.get(location)
        if coordinates is None:
            continue

        map_locations.append(
            {
                "location": location,
                "latitude": coordinates[0],
                "longitude": coordinates[1],
                "risk_level": country_risk_assignments.get(location, ""),
                "marker_color": RISK_CATEGORY_MAP_COLORS.get(
                    country_risk_assignments.get(location, ""),
                    DEFAULT_MAP_RISK_COLOR,
                ),
            }
        )

    high_risk_locations = [
        loc["location"]
        for loc in map_locations
        if loc["risk_level"] in ("High", "Very High")
    ]

    privacy_laws = str(latest_assessment.get("privacy_laws_adhered_to", "") or "").strip()
    return {
        "has_audit": True,
        "has_locations": bool(locations),
        "locations": locations,
        "map_locations": map_locations,
        "high_risk_locations": high_risk_locations,
        "vendor_assessment_date": latest_assessment.get("vendor_assessment_date", ""),
        "no_privacy_policy": bool(latest_assessment.get("no_vendor_privacy_policy", False)),
        "dpa_status": latest_assessment.get("dpa_status", ""),
        "no_privacy_laws": not bool(privacy_laws),
    }


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("index"))

    error_message = ""
    next_url = request.args.get("next", "") if request.method == "GET" else request.form.get("next", "")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == LOGIN_USERNAME and check_password_hash(LOGIN_PASSWORD_HASH, password):
            session["authenticated"] = True
            session["username"] = username
            if next_url and next_url.startswith("/"):
                return redirect(next_url)
            return redirect(url_for("index"))
        error_message = "Incorrect username or password."

    return render_template("login.html", error_message=error_message, next_url=next_url)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    show_all_upcoming_audits = request.args.get("show_upcoming") == "all"
    return render_template("index.html", **build_dashboard_context(show_all_upcoming_audits=show_all_upcoming_audits))


@app.route("/debug/routes")
def debug_routes():
    return jsonify(
        {
            "app_file": str(Path(__file__).resolve()),
            "routes": sorted(str(rule) for rule in app.url_map.iter_rules()),
        }
    )


@app.route("/software/<path:software_name>/audit-date", methods=["POST"])
def update_software_audit_date_from_dashboard(software_name):
    assessments = get_software_history(software_name)
    if not assessments:
        abort(404)

    next_audit_date = request.form.get("next_audit_date", "").strip()
    update_software_audit_date(software_name, next_audit_date)
    return redirect(url_for("index"))


@app.route("/software/<path:software_name>/purchase-link", methods=["POST"])
def save_software_purchase_link_route(software_name):
    purchase_link = request.form.get("purchase_link", "").strip()
    if not save_software_purchase_link(software_name, purchase_link):
        return jsonify({"ok": False, "error": "Software name is required"}), 400
    return jsonify({"ok": True, "purchase_link": purchase_link})


@app.route("/software/<path:software_name>/website", methods=["POST"])
def save_software_website_route(software_name):
    software_website = request.form.get("software_website", "").strip()
    if not save_software_website(software_name, software_website):
        return jsonify({"ok": False, "error": "Software name is required"}), 400
    return jsonify({"ok": True, "software_website": software_website})


@app.route("/software/<path:software_name>/license-agreement", methods=["POST"])
def save_software_license_agreement_link_route(software_name):
    license_agreement_link = request.form.get("license_agreement_link", "").strip()
    if not save_software_license_agreement_link(software_name, license_agreement_link):
        return jsonify({"ok": False, "error": "Software name is required"}), 400
    return jsonify({"ok": True, "license_agreement_link": license_agreement_link})


@app.route("/software/<path:software_name>/terms-conditions", methods=["POST"])
def save_software_terms_conditions_route(software_name):
    terms_conditions_link = request.form.get("terms_conditions_link", "").strip()
    if not save_software_terms_conditions_link(software_name, terms_conditions_link):
        return jsonify({"ok": False, "error": "Software name is required"}), 400
    return jsonify({"ok": True, "terms_conditions_link": terms_conditions_link})


@app.route("/software")
def software_list():
    return render_template("software_list.html", software_records=build_software_catalog())


def save_software_deployed_status(software_name, deployed):
    normalized = normalized_name(software_name)
    if not normalized:
        return False

    updated = False
    for record in SOFTWARE_RECORDS:
        if normalized_name(record.get("software_name", "")) == normalized:
            record["deployed"] = deployed
            record.update(enrich_assessment(record))
            updated = True
    for record in SOFTWARE_ITEMS:
        if normalized_name(record.get("software_name", "")) == normalized:
            record["deployed"] = deployed
            record.update(enrich_assessment(record))
            updated = True
    return updated

@app.route("/software-bulk-status", methods=["POST"])
def bulk_software_status():
    software_names = request.form.getlist("software_names")
    status = request.form.get("status", "").strip()
    if status not in ("active", "inactive"):
        return jsonify({"ok": False, "error": "Invalid status"}), 400

    deployed = status == "active"
    updated_count = sum(1 for name in software_names if save_software_deployed_status(name, deployed))
    if updated_count:
        persist_software_records()
    return jsonify({"ok": True, "updated": updated_count, "status": status})


@app.route("/reports")
def reports():
    return render_template(
        "reports.html",
        data_hosting_heatmap=build_data_hosting_heatmap(),
        vendors_with_unspecified_hosting_locations=build_vendors_with_unspecified_hosting_locations_report(),
        vendors_without_hosting_locations=build_vendors_without_hosting_locations_report(),
    )


@app.route("/reports/vendor-origins")
def vendor_origins():
    return render_template(
        "vendor_origins.html",
        vendor_origin_map=build_vendor_origin_map(),
    )


def build_age_restriction_chart_data():
    LEGAL_AGE_VALUE = "Users must be of legal age in their country OR have a parent/guardian accept the EULA on their behalf"
    LABEL_MAP = {
        "None": "None",
        "13+": "13+",
        "15+": "15+",
        "16+": "16+",
        "18+": "18+",
        LEGAL_AGE_VALUE: "Legal age in country",
    }
    categories = ["None", "13+", "15+", "16+", "18+", "Legal age in country", "Not set"]
    buckets = {cat: [] for cat in categories}

    for record in build_software_catalog(active_only=True):
        vendor_name = record.get("vendor_name", "")
        vendor_record = get_vendor_by_name(vendor_name) if vendor_name else None
        age = (
            (vendor_record or {}).get("vendor_age_restrictions", "")
            or record.get("age_restrictions", "")
        )
        label = LABEL_MAP.get(age, "Not set") if age else "Not set"
        buckets[label].append({
            "software_name": record.get("software_name", "Unknown"),
            "vendor_name": record.get("vendor_name", ""),
        })

    return {
        "categories": categories,
        "counts": [len(buckets[cat]) for cat in categories],
        "software_by_category": {cat: buckets[cat] for cat in categories},
    }


@app.route("/reports/age-restrictions")
def age_restriction_graph():
    return render_template(
        "age_restriction_graph.html",
        chart_data=build_age_restriction_chart_data(),
    )


def build_software_updates_chart_data():
    categories = ["Both Updates", "Product Updates Only", "Security Updates Only", "No Updates"]
    buckets = {cat: [] for cat in categories}

    for record in build_software_catalog(active_only=True):
        if not record.get("is_assessment"):
            continue
        product = bool(record.get("product_updates", False))
        security = bool(record.get("security_updates", False))
        if product and security:
            cat = "Both Updates"
        elif product:
            cat = "Product Updates Only"
        elif security:
            cat = "Security Updates Only"
        else:
            cat = "No Updates"
        buckets[cat].append({
            "software_name": record.get("software_name", "Unknown"),
            "vendor_name": record.get("vendor_name", ""),
        })

    return {
        "categories": categories,
        "counts": [len(buckets[cat]) for cat in categories],
        "software_by_category": {cat: buckets[cat] for cat in categories},
    }


@app.route("/reports/software-updates")
def software_updates_graph():
    return render_template(
        "software_updates_graph.html",
        chart_data=build_software_updates_chart_data(),
    )


@app.route("/categories")
def category_list():
    catalog = build_software_catalog(active_only=True)
    software_counts = {}
    uncategorised = []
    for record in catalog:
        cat_name = record.get("category", "").strip()
        if cat_name:
            software_counts[cat_name] = software_counts.get(cat_name, 0) + 1
        else:
            uncategorised.append(record)
    uncategorised.sort(key=lambda r: r.get("software_name", "").casefold())
    return render_template("category_list.html", categories=CATEGORIES, software_counts=software_counts, uncategorised=uncategorised)


@app.route("/categories/new", methods=["GET", "POST"])
def new_category():
    global NEXT_CATEGORY_ID
    error = None
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        genuine_need = request.form.get("genuine_need", "").strip()
        if not name:
            error = "Category name is required."
        elif not genuine_need:
            error = "Genuine need is required."
        elif get_category_by_name(name):
            error = f"A category named “{name}” already exists."
        else:
            CATEGORIES.append({"id": NEXT_CATEGORY_ID, "name": name, "genuine_need": genuine_need})
            NEXT_CATEGORY_ID += 1
            persist_categories()
            return redirect(url_for("category_list"))
    return render_template("new_category.html", error=error)


@app.route("/categories/<path:category_name>", methods=["GET", "POST"])
def category_detail(category_name):
    cat = get_category_by_name(category_name)
    if cat is None:
        abort(404)
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "delete":
            CATEGORIES.remove(cat)
            persist_categories()
            return redirect(url_for("category_list"))
    catalog = build_software_catalog(active_only=False)
    cat_cf = cat["name"].casefold()
    software = [r for r in catalog if r.get("category", "").strip().casefold() == cat_cf]
    return render_template(
        "category_detail.html",
        category=cat,
        software=software,
    )


@app.route("/categories/<path:category_name>/edit", methods=["GET", "POST"])
def category_edit(category_name):
    cat = get_category_by_name(category_name)
    if cat is None:
        abort(404)
    error = None
    if request.method == "POST":
        new_name = request.form.get("name", "").strip()
        genuine_need = request.form.get("genuine_need", "").strip()
        if not new_name:
            error = "Category name is required."
        elif not genuine_need:
            error = "Genuine need is required."
        elif new_name.casefold() != cat["name"].casefold() and get_category_by_name(new_name):
            error = f'A category named "{new_name}" already exists.'
        else:
            old_name = cat["name"]
            cat["name"] = new_name
            cat["genuine_need"] = genuine_need
            if old_name.casefold() != new_name.casefold():
                for record in SOFTWARE_RECORDS:
                    if record.get("category", "").strip().casefold() == old_name.casefold():
                        record["category"] = new_name
                persist_software_records()
            persist_categories()
            return redirect(url_for("category_detail", category_name=new_name))
    return render_template("category_edit.html", category=cat, error=error)


@app.route("/software/new", methods=["GET", "POST"])
def new_software():
    global NEXT_SOFTWARE_ID

    category_error = None
    if request.method == "POST":
        software_details = collect_software_form_data(request.form)
        if is_category_required() and not software_details["category"]:
            category_error = "A category is required."
        elif software_details["software_name"] and software_details["vendor_name"]:
            record = blank_assessment()
            for field in SOFTWARE_DETAIL_FIELDS:
                if field in software_details:
                    record[field] = software_details[field]
            record["deployed"] = True
            record["review_date"] = software_details["next_audit_date"]
            record["id"] = NEXT_SOFTWARE_ID
            record["software_id"] = NEXT_SOFTWARE_ID
            record["is_assessment"] = False
            enriched_record = enrich_assessment(record)
            SOFTWARE_RECORDS.append(enriched_record)
            sync_vendor_from_assessment(enriched_record)
            persist_software_records()
            persist_vendor_records()
            NEXT_SOFTWARE_ID += 1
            return redirect(url_for("software_detail", software_name=enriched_record["software_name"]))

    software = blank_assessment()
    if request.method == "POST":
        software.update(collect_software_form_data(request.form))

    return render_template(
        "software_edit.html",
        software=software,
        form_title="Add Software",
        submit_label="Save Software",
        is_new=True,
        category_error=category_error,
        category_required=is_category_required(),
        categories=CATEGORIES,
        **FORM_OPTION_CONTEXT,
    )


@app.route("/software/<path:software_name>/edit", methods=["GET", "POST"])
def edit_software(software_name):
    software_record = get_latest_software_record(software_name)
    if software_record is None:
        abort(404)

    if request.method == "POST":
        updated_details = collect_software_form_data(request.form)
        updated_details["vendor_country"] = software_record.get("vendor_country", "")
        if updated_details["software_name"] and updated_details["vendor_name"]:
            update_software_details(software_name, updated_details)
        return redirect(url_for("software_detail", software_name=updated_details.get("software_name") or software_name))

    software_item = get_software_item_by_name(software_name)
    form_record = dict(software_record)
    form_record["risk_level"] = software_item.get("risk_level", "") if software_item else software_record.get("risk_level", "")
    if software_item:
        form_record["product_updates"] = software_item.get("product_updates", False)
        form_record["security_updates"] = software_item.get("security_updates", False)
        form_record["support_notes"] = software_item.get("support_notes", "")
        form_record["tested"] = software_item.get("tested", False)
        form_record["category"] = software_item.get("category", "") or form_record.get("category", "")
        form_record["software_type"] = software_item.get("software_type", "")
        form_record["software_support"] = software_item.get("software_support", "")

    return render_template(
        "software_edit.html",
        software=form_record,
        form_title="Edit Software",
        submit_label="Update Software",
        is_new=False,
        category_error=None,
        category_required=is_category_required(),
        categories=CATEGORIES,
        **FORM_OPTION_CONTEXT,
    )


@app.route("/software/<path:software_name>/delete", methods=["POST"])
def delete_software(software_name):
    record = get_latest_software_record(software_name)
    if record is None:
        abort(404)

    delete_software_details(software_name)
    return redirect(url_for("software_list"))




@app.route("/software/<path:software_name>")
def software_detail(software_name):
    software_record = get_latest_software_record(software_name)
    if not software_record:
        abort(404)
    assessments = get_software_assessment_records(software_name)

    vendor_name = software_record.get("vendor_name", "")
    vendor_map = build_vendor_data_storage_map(vendor_name) if vendor_name else {"high_risk_locations": []}
    vendor_record = get_vendor_by_name(vendor_name) if vendor_name else None
    vendor_terms_conditions_link = (vendor_record or {}).get("vendor_terms_conditions_link", "")
    vendor_age_restrictions = (vendor_record or {}).get("vendor_age_restrictions", "")
    vendor_allows_acceptance = (vendor_record or {}).get("vendor_allows_acceptance_on_behalf_of_entity", "")
    vendor_online_support = (vendor_record or {}).get("online_support", "")

    software_item = get_software_item_by_name(software_name)
    display_record = dict(software_record)
    if software_item:
        display_record["next_audit_date"] = software_item.get("next_audit_date", "") or display_record.get("next_audit_date", "")
        display_record["audit_reminder_frequency"] = software_item.get("audit_reminder_frequency", "") or display_record.get("audit_reminder_frequency", "")
        display_record["category"] = software_item.get("category", "") or display_record.get("category", "")
        display_record["product_updates"] = software_item.get("product_updates", False)
        display_record["security_updates"] = software_item.get("security_updates", False)
        display_record["support_notes"] = software_item.get("support_notes", "")
        display_record["tested"] = software_item.get("tested", False)
        display_record["software_type"] = software_item.get("software_type", "")
        display_record["software_support"] = software_item.get("software_support", "")
    alert_keys = compute_software_alert_keys(display_record, vendor_record, vendor_map, get_home_country(), software_item)
    computed_risk = highest_risk_from_alerts(alert_keys)
    if not computed_risk and assessments:
        computed_risk = "Low"
    display_record["risk_level"] = computed_risk

    return render_template(
        "software_detail.html",
        software=display_record,
        software_name=software_record["software_name"],
        assessments=assessments,
        vendor_high_risk_locations=vendor_map["high_risk_locations"],
        vendor_data_storage_locations=vendor_map["locations"],
        vendor_no_privacy_policy=vendor_map.get("no_privacy_policy", False),
        vendor_no_privacy_laws=vendor_map.get("has_audit", False) and vendor_map.get("no_privacy_laws", False),
        vendor_dpa_status=vendor_map.get("dpa_status", ""),
        vendor_terms_conditions_link=vendor_terms_conditions_link,
        vendor_age_restrictions=vendor_age_restrictions,
        vendor_allows_acceptance=vendor_allows_acceptance,
        vendor_online_support=vendor_online_support,
        home_country=get_home_country(),
    )


def fetch_nvd_cves(keyword):
    """Returns {"cves": [...], "total": N} or None on any failure. Caches for NVD_CACHE_TTL seconds."""
    if not keyword:
        return None
    cache_key = keyword.casefold()
    cached = _nvd_cache.get(cache_key)
    if cached:
        cached_at, cached_data = cached
        if time.time() - cached_at < NVD_CACHE_TTL:
            return cached_data
    params = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": 15})
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}&noRejected"
    req = urllib.request.Request(url, headers={"User-Agent": "SoftwareSecurityAuditor/1.0"})
    if NVD_API_KEY:
        req.add_header("apiKey", NVD_API_KEY)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
        cves = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            if cve.get("vulnStatus", "").lower() == "rejected":
                continue
            description = next(
                (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "",
            )
            base_score = None
            severity = ""
            metrics = cve.get("metrics", {})
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key, [])
                if metric_list and isinstance(metric_list[0], dict):
                    cvss_data = metric_list[0].get("cvssData", {}) or {}
                    base_score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity", "")
                    break
            cves.append({
                "id": cve.get("id", ""),
                "description": description,
                "base_score": base_score,
                "severity": severity,
                "published": (cve.get("published", "") or "")[:10],
            })
    except Exception:
        return None
    result = {"cves": cves, "total": data.get("totalResults", 0)}
    _nvd_cache[cache_key] = (time.time(), result)
    return result


@app.route("/api/nvd/cves")
def nvd_cves():
    keyword = request.args.get("keyword", "").strip()
    if not keyword:
        return jsonify({"error": "keyword required"}), 400
    result = fetch_nvd_cves(keyword)
    if result is None:
        return jsonify({"error": "Could not load vulnerability data from NVD"}), 502
    return jsonify(result)


@app.route("/api/cve-status", methods=["GET", "POST"])
def cve_status():
    if request.method == "GET":
        software_name = request.args.get("name", "").strip()
        item = get_software_item_by_name(software_name) if software_name else None
        unrelated = list(item.get("unrelated_cves") or []) if item else []
        return jsonify({"unrelated_cves": unrelated})

    data = request.get_json(silent=True) or {}
    software_name = data.get("software_name", "").strip()
    cve_id = data.get("cve_id", "").strip()
    mark_unrelated = bool(data.get("unrelated", False))
    if not software_name or not cve_id:
        return jsonify({"error": "software_name and cve_id required"}), 400
    item = get_software_item_by_name(software_name)
    if item is None:
        return jsonify({"error": "software not found"}), 404
    cve_set = set(item.get("unrelated_cves") or [])
    if mark_unrelated:
        cve_set.add(cve_id)
    else:
        cve_set.discard(cve_id)
    item["unrelated_cves"] = sorted(cve_set)
    persist_software_items()
    return jsonify({"ok": True, "unrelated_cves": item["unrelated_cves"]})


@app.route("/vendors")
def vendor_list():
    return render_template("vendor_list.html", vendors=build_vendor_list())


def render_new_vendor_assessment_form(vendor):
    assessment = blank_vendor_assessment(vendor["vendor_name"])
    assessment["vendor_assessment_date"] = date.today().isoformat()
    assessment["vendor_audit_reminder_frequency"] = vendor.get("vendor_audit_reminder_frequency", "") or "1_year"
    return render_template(
        "vendor_assessment_form.html",
        vendor=vendor,
        assessment=assessment,
        home_country=get_home_country(),
        form_title="Add Vendor Audit",
        submit_label="Submit Vendor Audit",
        **FORM_OPTION_CONTEXT,
    )


def get_vendor_record_in_memory(vendor_name):
    n = normalized_name(vendor_name)
    return next((v for v in VENDOR_RECORDS if normalized_name(v.get("vendor_name", "")) == n), None)


def _delete_vendor_pdf_file(vendor_rec):
    old = vendor_rec.get("privacy_policy_pdf_filename", "")
    if old:
        try:
            (UPLOADS_DIR / old).unlink()
        except OSError:
            pass


def _delete_vendor_tc_pdf_file(vendor_rec):
    old = vendor_rec.get("vendor_tc_pdf_filename", "")
    if old:
        try:
            (UPLOADS_DIR / old).unlink()
        except OSError:
            pass


def handle_vendor_tc_pdf_upload(vendor_rec):
    if vendor_rec is None:
        return
    pdf_file = request.files.get("vendor_tc_pdf")
    if not pdf_file or not pdf_file.filename or not pdf_file.filename.lower().endswith(".pdf"):
        return
    _delete_vendor_tc_pdf_file(vendor_rec)
    filename = f"{uuid.uuid4().hex}.pdf"
    pdf_file.save(str(UPLOADS_DIR / filename))
    vendor_rec["vendor_tc_pdf_filename"] = filename
    vendor_rec["vendor_tc_pdf_original_name"] = pdf_file.filename
    persist_vendor_records()


def handle_vendor_privacy_policy_upload(vendor_rec):
    if vendor_rec is None:
        return
    pdf_file = request.files.get("privacy_policy_pdf")
    if not pdf_file or not pdf_file.filename or not pdf_file.filename.lower().endswith(".pdf"):
        return
    _delete_vendor_pdf_file(vendor_rec)
    filename = f"{uuid.uuid4().hex}.pdf"
    pdf_file.save(str(UPLOADS_DIR / filename))
    vendor_rec["privacy_policy_pdf_filename"] = filename
    vendor_rec["privacy_policy_pdf_original_name"] = pdf_file.filename
    persist_vendor_records()


def _delete_software_eula_pdf_file(software_rec):
    old = software_rec.get("eula_pdf_filename", "")
    if old:
        try:
            (UPLOADS_DIR / old).unlink()
        except OSError:
            pass


def handle_software_eula_pdf_upload(software_rec):
    if software_rec is None:
        return False
    pdf_file = request.files.get("eula_pdf")
    if not pdf_file or not pdf_file.filename or not pdf_file.filename.lower().endswith(".pdf"):
        return False
    _delete_software_eula_pdf_file(software_rec)
    filename = f"{uuid.uuid4().hex}.pdf"
    pdf_file.save(str(UPLOADS_DIR / filename))
    software_rec["eula_pdf_filename"] = filename
    software_rec["eula_pdf_original_name"] = pdf_file.filename
    return True


def get_software_eula_pdf_for_record(record):
    software = get_software_item_by_name(record.get("software_name", ""))
    if software is None:
        return ""
    return software.get("eula_pdf_original_name", "")


def save_new_vendor_assessment(vendor_name):
    global NEXT_VENDOR_ASSESSMENT_ID

    vendor = build_vendor_context(vendor_name)
    updated_vendor = collect_vendor_form_data(request.form)
    if updated_vendor["vendor_name"]:
        updated_vendor["vendor_next_audit_date"] = (
            updated_vendor["vendor_next_audit_date"] or vendor.get("vendor_next_audit_date", "")
        )
        update_vendor_details(vendor_name, updated_vendor)
        vendor = get_vendor_record_or_none(updated_vendor["vendor_name"]) or updated_vendor

    handle_vendor_privacy_policy_upload(get_vendor_record_in_memory(vendor["vendor_name"]))
    handle_vendor_tc_pdf_upload(get_vendor_record_in_memory(vendor["vendor_name"]))

    assessment = collect_vendor_assessment_form_data(request.form, NEXT_VENDOR_ASSESSMENT_ID)
    assessment["vendor_name"] = vendor["vendor_name"]
    VENDOR_ASSESSMENT_RECORDS.append(assessment)
    sync_vendor_schedule_from_assessment(assessment)
    persist_vendor_assessment_records()
    NEXT_VENDOR_ASSESSMENT_ID += 1
    return redirect(url_for("vendor_detail", vendor_name=vendor["vendor_name"]))


@app.route("/vendors/<path:vendor_name>/terms-student-data", methods=["POST"])
def update_vendor_terms_student_data(vendor_name):
    vendor = build_vendor_context(vendor_name)
    vendor["vendor_age_restrictions"] = request.form.get("vendor_age_restrictions", "").strip()
    vendor["vendor_allows_acceptance_on_behalf_of_entity"] = request.form.get("vendor_allows_acceptance_on_behalf_of_entity", "").strip()
    vendor["vendor_terms_conditions_notes"] = request.form.get("vendor_terms_conditions_notes", "").strip()
    update_vendor_details(vendor_name, vendor)
    return jsonify({"ok": True})


@app.route("/vendors/<path:vendor_name>", methods=["GET", "POST"])
def vendor_detail(vendor_name):
    if vendor_name.endswith("/assessments/new"):
        clean_vendor_name = vendor_name.removesuffix("/assessments/new")
        if request.method == "POST":
            return save_new_vendor_assessment(clean_vendor_name)
        return render_new_vendor_assessment_form(build_vendor_context(clean_vendor_name))

    vendor = build_vendor_context(vendor_name)

    linked_software = get_vendor_linked_software(vendor_name)
    return render_template(
        "vendor_detail.html",
        vendor=vendor,
        linked_software=linked_software,
        vendor_assessments=get_vendor_assessments(vendor_name),
        vendor_data_storage_map=build_vendor_data_storage_map(vendor_name),
    )


@app.route("/countries/<path:country_name>/comments/<int:comment_id>/delete", methods=["POST"])
def delete_country_risk_comment(country_name, comment_id):
    if country_name not in COUNTRY_OPTIONS:
        abort(404)
    with get_db_connection() as conn:
        conn.execute(
            "DELETE FROM country_risk_comments WHERE id = ? AND country = ?",
            (comment_id, country_name),
        )
    return redirect(url_for("country_detail", country_name=country_name))


@app.route("/countries/<path:country_name>", methods=["GET", "POST"])
def country_detail(country_name):
    if country_name not in COUNTRY_OPTIONS:
        abort(404)

    if request.method == "POST":
        new_risk = request.form.get("risk_level", "").strip()
        comment = request.form.get("comment", "").strip()
        if new_risk in RISK_CATEGORY_OPTIONS:
            with get_db_connection() as conn:
                conn.execute(
                    "INSERT INTO country_risk_comments (country, risk_level, comment, created_at) VALUES (?, ?, ?, ?)",
                    (country_name, new_risk, comment, datetime.now().strftime("%Y-%m-%d %H:%M")),
                )
        return redirect(url_for("country_detail", country_name=country_name))

    vendors_hosting = []
    vendors_based = []
    for vendor in build_vendor_list():
        vendor_name = vendor.get("vendor_name", "")
        if vendor.get("vendor_country", "") == country_name:
            vendors_based.append(vendor)
        assessment = get_latest_vendor_assessment(vendor_name)
        locations = get_selected_values((assessment or {}).get("data_storage_location", ""))
        if country_name in locations:
            vendors_hosting.append(vendor)

    return render_template(
        "country_detail.html",
        country_name=country_name,
        risk_level=get_country_risk_level(country_name),
        risk_comments=get_country_risk_comments(country_name),
        vendors_hosting=vendors_hosting,
        vendors_based=vendors_based,
        risk_category_options=RISK_CATEGORY_OPTIONS,
    )


@app.route("/settings", methods=["GET", "POST"])
def settings():
    saved = False
    if request.method == "POST":
        APP_SETTINGS["reminder_email"] = request.form.get("reminder_email", "").strip()
        home_country = request.form.get("home_country", "").strip()
        APP_SETTINGS["home_country"] = home_country if home_country in COUNTRY_OPTIONS else DEFAULT_APP_SETTINGS["home_country"]
        APP_SETTINGS["country_risk_assignments"] = json.dumps(
            normalize_country_risk_assignments(request.form.get("country_risk_assignments", "{}"))
        )
        APP_SETTINGS["dark_mode"] = "true" if request.form.get("dark_mode") == "true" else "false"
        APP_SETTINGS["category_required"] = "true" if request.form.get("category_required") == "true" else "false"
        raw_signatory = {}
        for role in SIGNATORY_ROLES:
            key = "signatory_" + role.lower().replace(" ", "_")
            raw_signatory[role] = request.form.getlist(key)
        APP_SETTINGS["signatory_alerts"] = json.dumps(normalize_signatory_alerts(raw_signatory))
        raw_alert_risks = {}
        for alert_key in PDF_ALERT_LABELS:
            raw_alert_risks[alert_key] = request.form.get("alert_risk_" + alert_key, "").strip()
        APP_SETTINGS["alert_risk_levels"] = json.dumps(normalize_alert_risk_levels(raw_alert_risks))
        raw_visibility = {alert_key: request.form.get("alert_visible_" + alert_key) == "true" for alert_key in PDF_ALERT_LABELS}
        APP_SETTINGS["alert_pdf_visibility"] = json.dumps(normalize_alert_pdf_visibility(raw_visibility))
        persist_app_settings()
        saved = True

    return render_template(
        "settings.html",
        settings=APP_SETTINGS,
        saved=saved,
        country_options=COUNTRY_OPTIONS,
        risk_category_options=RISK_CATEGORY_OPTIONS,
        country_risk_assignments=get_country_risk_assignments(),
        signatory_roles=SIGNATORY_ROLES,
        pdf_alert_labels=PDF_ALERT_LABELS,
        signatory_alerts=get_signatory_alerts(),
        alert_risk_levels=get_alert_risk_levels(),
        alert_pdf_visibility=get_alert_pdf_visibility(),
    )


@app.route("/vendors/new", methods=["GET", "POST"])
def new_vendor():
    if request.method == "POST":
        vendor_data = collect_vendor_form_data(request.form)
        if vendor_data["vendor_name"]:
            existing_names = {normalized_name(vendor["vendor_name"]) for vendor in build_vendor_list()}
            if normalized_name(vendor_data["vendor_name"]) not in existing_names:
                VENDOR_RECORDS.append(vendor_data)
                persist_vendor_records()
        return redirect(url_for("vendor_list"))

    return render_template(
        "vendor_form.html",
        vendor=blank_vendor(),
        form_title="Add New Vendor",
        submit_label="Save Vendor",
        is_edit=False,
        **FORM_OPTION_CONTEXT,
    )


@app.route("/vendors/<path:vendor_name>/edit", methods=["GET", "POST"])
def edit_vendor(vendor_name):
    vendor = build_vendor_context(vendor_name)

    if request.method == "POST":
        updated_vendor = collect_vendor_form_data(request.form)
        if updated_vendor["vendor_name"]:
            update_vendor_details(vendor_name, updated_vendor)
        return redirect(url_for("vendor_detail", vendor_name=updated_vendor.get("vendor_name") or vendor_name))

    return render_template(
        "vendor_form.html",
        vendor=vendor,
        original_vendor_name=vendor["vendor_name"],
        form_title="Edit Vendor",
        submit_label="Update Vendor",
        is_edit=True,
        **FORM_OPTION_CONTEXT,
    )


@app.route("/vendors/<path:vendor_name>/assessments/new", methods=["GET", "POST"])
@app.route("/vendor-assessments/new/<path:vendor_name>", methods=["GET", "POST"])
def new_vendor_assessment(vendor_name):
    vendor = build_vendor_context(vendor_name)

    if request.method == "POST":
        return save_new_vendor_assessment(vendor_name)

    return render_new_vendor_assessment_form(vendor)


@app.route("/vendor-assessments/<int:assessment_id>/edit", methods=["GET", "POST"])
def edit_vendor_assessment(assessment_id):
    assessment = get_vendor_assessment_or_none(assessment_id)
    if assessment is None:
        abort(404)

    vendor = build_vendor_context(assessment.get("vendor_name", ""))

    if request.method == "POST":
        updated_vendor = collect_vendor_form_data(request.form)
        if updated_vendor["vendor_name"]:
            updated_vendor["vendor_next_audit_date"] = (
                updated_vendor["vendor_next_audit_date"] or vendor.get("vendor_next_audit_date", "")
            )
            update_vendor_details(vendor["vendor_name"], updated_vendor)
            vendor = get_vendor_record_or_none(updated_vendor["vendor_name"]) or updated_vendor

        handle_vendor_privacy_policy_upload(get_vendor_record_in_memory(vendor["vendor_name"]))
        handle_vendor_tc_pdf_upload(get_vendor_record_in_memory(vendor["vendor_name"]))

        updated_assessment = collect_vendor_assessment_form_data(request.form, assessment_id)
        updated_assessment["vendor_name"] = vendor["vendor_name"]
        index = VENDOR_ASSESSMENT_RECORDS.index(assessment)
        VENDOR_ASSESSMENT_RECORDS[index] = updated_assessment
        sync_vendor_schedule_from_assessment(updated_assessment)
        persist_vendor_assessment_records()
        return redirect(url_for("vendor_detail", vendor_name=vendor["vendor_name"]))

    return render_template(
        "vendor_assessment_form.html",
        vendor=vendor,
        assessment=assessment,
        home_country=get_home_country(),
        form_title="Edit Vendor Audit",
        submit_label="Update Vendor Audit",
        **FORM_OPTION_CONTEXT,
    )


@app.route("/vendors/<path:vendor_name>/delete", methods=["POST"])
def delete_vendor(vendor_name):
    vendor = get_vendor_record_or_none(vendor_name)
    if vendor is None:
        abort(404)

    delete_vendor_details(vendor_name)
    return redirect(url_for("vendor_list"))


@app.route("/vendors/<path:vendor_name>/privacy-policy", methods=["POST"])
def save_vendor_privacy_policy(vendor_name):
    if get_vendor_by_name(vendor_name) is None:
        return jsonify({"ok": False, "error": "Vendor not found"}), 404

    privacy_policy_link = request.form.get("vendor_privacy_policy_link", "").strip()
    save_vendor_privacy_policy_link(vendor_name, privacy_policy_link)
    return jsonify({"ok": True, "vendor_privacy_policy_link": privacy_policy_link})


@app.route("/vendor-privacy-policy/clear", methods=["POST"])
def clear_vendor_privacy_policy_pdf():
    vendor_name = request.form.get("vendor_name", "").strip()
    vendor_rec = get_vendor_record_in_memory(vendor_name)
    if vendor_rec is None:
        return jsonify({"ok": False, "error": "Vendor not found"}), 404
    _delete_vendor_pdf_file(vendor_rec)
    vendor_rec["privacy_policy_pdf_filename"] = ""
    vendor_rec["privacy_policy_pdf_original_name"] = ""
    persist_vendor_records()
    return jsonify({"ok": True})


@app.route("/vendor-tc-pdf/clear", methods=["POST"])
def clear_vendor_tc_pdf():
    vendor_name = request.form.get("vendor_name", "").strip()
    vendor_rec = get_vendor_record_in_memory(vendor_name)
    if vendor_rec is None:
        return jsonify({"ok": False, "error": "Vendor not found"}), 404
    _delete_vendor_tc_pdf_file(vendor_rec)
    vendor_rec["vendor_tc_pdf_filename"] = ""
    vendor_rec["vendor_tc_pdf_original_name"] = ""
    persist_vendor_records()
    return jsonify({"ok": True})


@app.route("/software-eula-pdf/clear", methods=["POST"])
def clear_software_eula_pdf():
    software_name = request.form.get("software_name", "").strip()
    software_rec = get_software_item_by_name(software_name)
    if software_rec is None:
        return jsonify({"ok": False, "error": "Software not found"}), 404
    _delete_software_eula_pdf_file(software_rec)
    software_rec["eula_pdf_filename"] = ""
    software_rec["eula_pdf_original_name"] = ""
    persist_software_items()
    return jsonify({"ok": True})


@app.route("/vendors/<path:vendor_name>/website", methods=["POST"])
def save_vendor_website(vendor_name):
    if get_vendor_by_name(vendor_name) is None:
        return jsonify({"ok": False, "error": "Vendor not found"}), 404

    website_link = request.form.get("vendor_website", "").strip()
    save_vendor_website_link(vendor_name, website_link)
    return jsonify({"ok": True, "vendor_website": website_link})


@app.route("/vendors/<path:vendor_name>/terms-conditions", methods=["POST"])
def save_vendor_terms_conditions(vendor_name):
    if get_vendor_by_name(vendor_name) is None:
        return jsonify({"ok": False, "error": "Vendor not found"}), 404

    terms_conditions_link = request.form.get("vendor_terms_conditions_link", "").strip()
    save_vendor_terms_conditions_link(vendor_name, terms_conditions_link)
    return jsonify({"ok": True, "vendor_terms_conditions_link": terms_conditions_link})


@app.route("/vendors/<path:vendor_name>/cookie-policy", methods=["POST"])
def save_vendor_cookie_policy(vendor_name):
    if get_vendor_by_name(vendor_name) is None:
        return jsonify({"ok": False, "error": "Vendor not found"}), 404

    cookie_policy_link = request.form.get("vendor_cookie_policy_link", "").strip()
    save_vendor_cookie_policy_link(vendor_name, cookie_policy_link)
    return jsonify({"ok": True, "vendor_cookie_policy_link": cookie_policy_link})


@app.route("/vendors/<path:vendor_name>/online-support", methods=["POST"])
def save_vendor_online_support(vendor_name):
    if get_vendor_by_name(vendor_name) is None:
        return jsonify({"ok": False, "error": "Vendor not found"}), 404

    support_link = request.form.get("online_support", "").strip()
    save_vendor_online_support_link(vendor_name, support_link)
    return jsonify({"ok": True, "online_support": support_link})



@app.route("/api/vendors/search")
def vendor_search():
    query = normalized_name(request.args.get("q", ""))
    vendors = build_vendor_list()

    if not query:
        matches = vendors[:8]
    else:
        starts_with = [vendor for vendor in vendors if normalized_name(vendor["vendor_name"]).startswith(query)]
        contains = [
            vendor for vendor in vendors
            if query in normalized_name(vendor["vendor_name"]) and vendor not in starts_with
        ]
        matches = (starts_with + contains)[:8]

    return jsonify(matches)


@app.route("/assessment/new", methods=["GET", "POST"])
def new_assessment():
    global NEXT_ASSESSMENT_ID

    if request.method == "POST":
        submit_action = request.form.get("submit_action", "submit")
        assessment_id = request.form.get("assessment_id", type=int)
        form_data = collect_assessment_form_data(request.form, assessment_id)
        save_vendor_terms_from_assessment_form(request.form)
        form_data["is_assessment"] = True
        if submit_action == "draft":
            form_data["submission_status"] = "draft"
        else:
            form_data["submission_status"] = "submitted"
            existing_record = get_assessment_or_none(assessment_id) if assessment_id is not None else None
            submitted_date = (existing_record or {}).get("submitted_date") or date.today().isoformat()
            form_data["submitted_date"] = submitted_date
            form_data["assessment_date"] = submitted_date
            normalize_submitted_audit_dates(form_data)
        existing_record = get_assessment_or_none(assessment_id) if assessment_id is not None else None
        form_data = enrich_assessment(form_data)
        if existing_record is None:
            SOFTWARE_RECORDS.append(form_data)
            NEXT_ASSESSMENT_ID = max(NEXT_ASSESSMENT_ID, (assessment_id or 0) + 1)
        else:
            index = SOFTWARE_RECORDS.index(existing_record)
            SOFTWARE_RECORDS[index] = form_data
        sync_vendor_from_assessment(form_data)
        if submit_action != "draft":
            advance_software_next_audit_after_submission(form_data)
        persist_software_records()
        persist_vendor_records()
        _eula_item = get_software_item_by_name(form_data.get("software_name", ""))
        if _eula_item is not None and handle_software_eula_pdf_upload(_eula_item):
            persist_software_items()
        return redirect(url_for("software_detail", software_name=form_data["software_name"]))

    draft_id = request.args.get("draft_id", type=int)
    source_software_name = request.args.get("source_software_name", "").strip()
    if draft_id is not None:
        draft_record = get_assessment_or_none(draft_id)
        if draft_record is not None and draft_record.get("submission_status") == "draft":
            return render_template(
                "assessment_form.html",
                assessment=draft_record,
                assessment_id=draft_record["id"],
                assessment_date=draft_record.get("assessment_date", "") or date.today().isoformat(),
                software_purchase_link=get_software_purchase_link_for_record(draft_record),
                vendor_terms_conditions_link=get_vendor_terms_link_for_record(draft_record),
                vendor_privacy_policy_link=get_vendor_privacy_policy_link_for_record(draft_record),
                vendor_age_restrictions=get_vendor_age_restrictions_for_record(draft_record),
                vendor_terms_conditions_notes=get_vendor_terms_conditions_notes_for_record(draft_record),
                vendor_allows_acceptance=get_vendor_allows_acceptance_for_record(draft_record),
                eula_pdf_original_name=get_software_eula_pdf_for_record(draft_record),
                form_title="New Software Assessment",
                submit_label="Submit Assessment",
                is_edit=False,
                software_details_editable=True,
                autosave_enabled=True,
                **FORM_OPTION_CONTEXT,
            )

    source_assessment = get_latest_software_record(source_software_name) if source_software_name else None
    draft_record = build_prefilled_assessment(source_assessment)
    draft_record["id"] = NEXT_ASSESSMENT_ID
    draft_record["is_assessment"] = True
    draft_record["submission_status"] = "draft"
    draft_record["assessment_date"] = ""
    draft_record["submitted_date"] = ""
    enriched_draft = enrich_assessment(draft_record)
    SOFTWARE_RECORDS.append(enriched_draft)
    persist_software_records()
    NEXT_ASSESSMENT_ID += 1
    return redirect(
        url_for(
            "new_assessment",
            draft_id=enriched_draft["id"],
            source_software_name=source_software_name,
        )
    )


@app.route("/assessment/<int:assessment_id>/edit", methods=["GET", "POST"])
def edit_assessment(assessment_id):
    record = get_assessment_or_none(assessment_id)
    if record is None:
        return ("Assessment not found", 404)

    if request.method == "POST":
        submit_action = request.form.get("submit_action", record.get("submission_status") or "draft")
        updated_record = collect_assessment_form_data(request.form, assessment_id)
        save_vendor_terms_from_assessment_form(request.form)
        updated_record["is_assessment"] = True
        if submit_action == "submit":
            updated_record["submission_status"] = "submitted"
            submitted_date = record.get("submitted_date") or date.today().isoformat()
            updated_record["submitted_date"] = submitted_date
            updated_record["assessment_date"] = submitted_date
            normalize_submitted_audit_dates(updated_record)
        else:
            updated_record["submission_status"] = "draft"
        updated_record = enrich_assessment(updated_record)
        index = SOFTWARE_RECORDS.index(record)
        SOFTWARE_RECORDS[index] = updated_record
        sync_vendor_from_assessment(updated_record)
        if submit_action == "submit":
            advance_software_next_audit_after_submission(updated_record)
        persist_software_records()
        persist_vendor_records()
        _eula_item = get_software_item_by_name(updated_record.get("software_name", ""))
        if _eula_item is not None and handle_software_eula_pdf_upload(_eula_item):
            persist_software_items()
        return redirect(url_for("software_detail", software_name=updated_record["software_name"]))

    return render_template(
        "assessment_form.html",
        assessment=record,
        assessment_id=assessment_id,
        assessment_date=record.get("assessment_date", ""),
        software_purchase_link=get_software_purchase_link_for_record(record),
        vendor_terms_conditions_link=get_vendor_terms_link_for_record(record),
        vendor_privacy_policy_link=get_vendor_privacy_policy_link_for_record(record),
        vendor_age_restrictions=get_vendor_age_restrictions_for_record(record),
        vendor_terms_conditions_notes=get_vendor_terms_conditions_notes_for_record(record),
        vendor_allows_acceptance=get_vendor_allows_acceptance_for_record(record),
        eula_pdf_original_name=get_software_eula_pdf_for_record(record),
        form_title="Edit Software Assessment",
        submit_label="Submit Assessment",
        is_edit=True,
        software_details_editable=False,
        autosave_enabled=False,
        **FORM_OPTION_CONTEXT,
    )


@app.route("/assessment/<int:assessment_id>/draft", methods=["POST"])
def autosave_assessment_draft(assessment_id):
    record = get_assessment_or_none(assessment_id)
    if record is None or record.get("submission_status") != "draft":
        return jsonify({"ok": False, "error": "Draft not found"}), 404

    draft_record = collect_assessment_form_data(request.form, assessment_id)
    save_vendor_terms_from_assessment_form(request.form)
    draft_record["is_assessment"] = True
    draft_record["submission_status"] = "draft"
    index = SOFTWARE_RECORDS.index(record)
    SOFTWARE_RECORDS[index] = draft_record
    sync_vendor_from_assessment(draft_record)
    persist_software_records()
    persist_vendor_records()
    _eula_item = get_software_item_by_name(draft_record.get("software_name", ""))
    if _eula_item is not None and handle_software_eula_pdf_upload(_eula_item):
        persist_software_items()
    return jsonify(
        {
            "ok": True,
            "assessment_id": assessment_id,
            "submission_status": "draft",
            "saved_at": datetime.now().strftime("%H:%M:%S"),
        }
    )


@app.route("/assessment/<int:assessment_id>/pdf")
def download_assessment_pdf(assessment_id):
    record = get_assessment_or_none(assessment_id)
    if record is None:
        return ("Assessment not found", 404)

    pdf_record = dict(record)
    pdf_record["vendor_terms_conditions_link"] = (
        record.get("vendor_terms_conditions_link") or get_vendor_terms_link_for_record(record)
    )
    pdf_record["terms_conditions_link"] = (
        record.get("terms_conditions_link") or pdf_record["vendor_terms_conditions_link"]
    )
    pdf_record["vendor_privacy_policy_link"] = (
        record.get("vendor_privacy_policy_link") or get_vendor_privacy_policy_link_for_record(record)
    )
    pdf_record["purchase_link"] = record.get("purchase_link") or get_software_purchase_link_for_record(record)
    if not record.get("terms_conditions_link"):
        vendor_record = get_vendor_by_name(record.get("vendor_name", ""))
        if vendor_record:
            pdf_record["age_restrictions"] = vendor_record.get("vendor_age_restrictions", "") or record.get("age_restrictions", "")
            pdf_record["terms_compliance_notes"] = vendor_record.get("vendor_terms_conditions_notes", "") or record.get("terms_compliance_notes", "")
            pdf_record["allows_acceptance_on_behalf_of_entity"] = vendor_record.get("vendor_allows_acceptance_on_behalf_of_entity", "") or record.get("allows_acceptance_on_behalf_of_entity", "")
    live_vendor = get_vendor_by_name(record.get("vendor_name", ""))
    pdf_record["online_support"] = (live_vendor or {}).get("online_support", "") or record.get("online_support", "")
    pdf_record["no_vendor_terms_conditions"] = bool((live_vendor or {}).get("no_vendor_terms_conditions", False))
    vendor = get_latest_vendor_assessment(record.get("vendor_name", "")) or {}
    for field in VENDOR_PRIVACY_FIELDS:
        pdf_record[field] = vendor.get(field, "")
    for field in PDF_HIDDEN_FIELDS:
        pdf_record.pop(field, None)
    pdf_record["vendor_security_assessment"] = vendor.get(
        "vendor_security_assessment",
        record.get("vendor_security_assessment", ""),
    )
    software_item = next(
        (item for item in SOFTWARE_ITEMS
         if normalized_name(item.get("software_name", "")) == normalized_name(record.get("software_name", ""))),
        None,
    )
    _pdf_vendor_name = pdf_record.get("vendor_name", "")
    _pdf_vendor_map = build_vendor_data_storage_map(_pdf_vendor_name) if _pdf_vendor_name else {
        "high_risk_locations": [], "locations": [], "no_privacy_policy": False, "dpa_status": "",
    }
    pdf_record["risk_level"] = highest_risk_from_alerts(
        compute_software_alert_keys(pdf_record, live_vendor or {}, _pdf_vendor_map, get_home_country(), software_item)
    )
    pdf_record["category"] = (software_item.get("category", "") if software_item else "") or record.get("category", "")
    if software_item:
        pdf_record["product_updates"] = software_item.get("product_updates", False)
        pdf_record["security_updates"] = software_item.get("security_updates", False)
        pdf_record["support_notes"] = software_item.get("support_notes", "")
        pdf_record["tested"] = software_item.get("tested", False)
        pdf_record["software_type"] = software_item.get("software_type", "")
    cat_obj = get_category_by_name(pdf_record.get("category", ""))
    pdf_record["genuine_need"] = cat_obj["genuine_need"] if cat_obj else ""
    safe_name = (record.get("software_name") or f"assessment-{assessment_id}").strip().replace(" ", "-")
    audit_date = (
        record.get("assessment_date")
        or record.get("next_audit_date")
        or f"assessment-{assessment_id}"
    )
    cve_data = fetch_nvd_cves(pdf_record.get("software_name", ""))
    if cve_data and software_item:
        unrelated = set(software_item.get("unrelated_cves") or [])
        if unrelated:
            filtered_cves = [c for c in cve_data.get("cves", []) if c["id"] not in unrelated]
            cve_data = {"cves": filtered_cves, "total": len(filtered_cves)} if filtered_cves else None
    pdf_data = build_assessment_pdf(pdf_record, cve_data=cve_data)
    return send_file(
        pdf_data,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{safe_name}-{audit_date}-audit-report.pdf",
    )


@app.route("/assessment/<int:assessment_id>/delete", methods=["POST"])
def delete_assessment(assessment_id):
    record = get_assessment_or_none(assessment_id)
    if record is None:
        return ("Assessment not found", 404)

    software_name = record.get("software_name", "")
    SOFTWARE_RECORDS.remove(record)
    persist_software_records()
    if software_name:
        return redirect(url_for("software_detail", software_name=software_name))
    return redirect(url_for("software_list"))


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
