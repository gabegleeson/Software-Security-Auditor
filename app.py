from calendar import monthrange
from collections import Counter, defaultdict
from datetime import date, datetime
from io import BytesIO
import json
import os
from pathlib import Path
import sqlite3
from xml.sax.saxutils import escape

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, session, url_for
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Image as PlatypusImage, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY", "change-this-secret-key")
DB_DIRECTORY = Path(__file__).resolve().parent / ".venv" / "data"
DB_PATH = DB_DIRECTORY / "software_auditor.db"
PDF_LOGO_PATH = Path(r"C:\Users\ggleeson\OneDrive - St Patricks College\IT Department - SPC Username Assistant\image\logo.jpg")
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
    "version",
    "free_software",
    "currency_type",
    "license_cost",
    "purchase_link",
    "duplicates_existing",
    "genuine_need_notes",
    "vendor_security_assessment",
    "product_security_assessment",
    "product_updates",
    "security_updates",
    "vendor_support",
    "support_notes",
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
    "license_renewal_date",
    "deployment_groups",
    "deployment_type",
    "tested",
    "deployed",
    "deployment_date",
    "audit_reminder_frequency",
    "review_date",
    "next_audit_date",
    "risk_level",
    "submitted_date",
    "software_id",
    "is_assessment",
    "submission_status",
)

CHECKBOX_FIELDS = {
    "free_software",
    "product_updates",
    "security_updates",
    "vendor_support",
    "allows_acceptance_on_behalf_of_entity",
    "tested",
    "deployed",
}
VENDOR_PRIVACY_FIELDS = (
    "data_processing_agreement_in_place",
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
    "vendor_privacy_policy_link",
    "online_support",
    "vendor_audit_reminder_frequency",
    "vendor_next_audit_date",
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
    "PIPEDA (Canada)",
    "LGPD (Brazil)",
)
SECURITY_PRIVACY_STANDARD_OPTIONS = (
    "ISO/IEC 27001",
    "ISO/IEC 27017",
    "ISO/IEC 27018",
    "ISO/IEC 27701",
    "ISO/IEC 42001",
    "CSA STAR Level 1",
    "CSA STAR Level 2",
    "SOC 1",
    "SOC 2",
    "SOC 3",
    "NIST Cybersecurity Framework",
    "FedRAMP",
    "APEC Privacy Framework (Asia-Pacific)",
    "PCI DSS",
    "CIS Controls",
)
SECTOR_SPECIFIC_CONTEXTUAL_LAW_OPTIONS = (
    "HIPAA",
    "FERPA",
    "SOX",
    "COPPA",
    "GLBA",
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
    "vendor_website": "Vendor Website",
    "vendor_terms_conditions_link": "Vendor Terms and Conditions Link",
    "terms_conditions_link": "Terms and Conditions Link",
    "vendor_privacy_policy_link": "Vendor Privacy Policy Link",
    "license_agreement_link": "License Agreement Link",
    "license_type": "License Type",
    "version": "Version",
    "free_software": "Free Software",
    "license_cost": "License Cost",
    "purchase_link": "Purchase Link",
    "duplicates_existing": "Duplicates Existing Capability",
    "genuine_need_notes": "Genuine Need Notes",
    "data_processing_agreement_in_place": "Data Processing Agreement in Place",
    "data_storage_location": "Data Storage Location",
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
    "product_security_assessment": "Product Security Assessment",
    "product_updates": "Product Updates",
    "security_updates": "Security Updates",
    "vendor_support": "Vendor Support",
    "support_notes": "Support Notes",
    "age_restrictions": "Age Restrictions",
    "allows_acceptance_on_behalf_of_entity": "Allows Acceptance on Behalf of an Entity",
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
    "license_renewal_date": "License Renewal Date",
    "deployment_type": "Deployment Type",
    "tested": "Tested",
    "deployed": "Deployed",
    "deployment_date": "Deployment Date",
    "audit_reminder_frequency": "Audit Reminder Schedule",
    "review_date": "Review Date",
    "next_audit_date": "Next Audit Date",
    "risk_level": "Risk Level",
}

PDF_SECTION_FIELDS = [
    ("Vendor Information", [
        "vendor_name",
        "vendor_country",
        "vendor_website",
        "vendor_terms_conditions_link",
        "vendor_privacy_policy_link",
        "vendor_security_assessment",
        "data_processing_agreement_in_place",
        "data_storage_location",
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
    ("Software Information", [
        "software_name",
        "software_description",
        "software_website",
        "terms_conditions_link",
        "license_agreement_link",
        "license_type",
        "version",
        "free_software",
        "license_cost",
        "purchase_link",
        "duplicates_existing",
        "genuine_need_notes",
        "product_security_assessment",
        "product_updates",
        "security_updates",
        "vendor_support",
        "support_notes",
        "software_license_details",
        "license_renewal_date",
        "deployment_date",
        "next_audit_date",
    ]),
    ("Assessment Responses", [
        "assessment_date",
        "age_restrictions",
        "allows_acceptance_on_behalf_of_entity",
        "terms_compliance_notes",
        "compatible_end_user_devices",
        "end_user_device_notes",
        "compatible_infrastructure",
        "infrastructure_notes",
        "supports_m365_sso",
        "integration_notes",
        "deployment_type",
        "tested",
        "deployed",
        "risk_level",
    ]),
]

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
    "terms_conditions_link",
    "license_agreement_link",
    "license_type",
    "purchase_link",
    "duplicates_existing",
    "genuine_need_notes",
    "product_security_assessment",
    "product_updates",
    "security_updates",
    "vendor_support",
    "support_notes",
    "software_license_details",
    "license_renewal_date",
    "deployment_groups",
    "tested",
    "deployed",
    "deployment_date",
    "audit_reminder_frequency",
    "next_audit_date",
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
        "terms_conditions_link": form.get("terms_conditions_link", "").strip(),
        "license_agreement_link": form.get("license_agreement_link", "").strip(),
        "license_type": license_type,
        "purchase_link": form.get("purchase_link", "").strip(),
        "duplicates_existing": form.get("duplicates_existing", "").strip(),
        "genuine_need_notes": form.get("genuine_need_notes", "").strip(),
        "product_security_assessment": form.get("product_security_assessment", "").strip(),
        "product_updates": "product_updates" in form,
        "security_updates": "security_updates" in form,
        "vendor_support": "vendor_support" in form,
        "support_notes": form.get("support_notes", "").strip(),
        "software_license_details": form.get("software_license_details", "").strip(),
        "license_renewal_date": license_renewal_date,
        "deployment_groups": form.get("deployment_groups", "").strip(),
        "tested": "tested" in form,
        "deployed": "deployed" in form,
        "deployment_date": form.get("deployment_date", "").strip(),
        "audit_reminder_frequency": form.get("audit_reminder_frequency", "").strip() or "1_year",
        "next_audit_date": form.get("next_audit_date", "").strip(),
    }


def determine_assessment_date(record, fallback_date=None):
    candidate_dates = [
        record.get("submitted_date", ""),
        record.get("assessment_date", ""),
        record.get("approval_date", ""),
        record.get("deployment_date", ""),
        fallback_date or "",
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
    if not risk_level:
        storage_locations = get_selected_values(get_vendor_backed_value(record, "data_storage_location"))
        if storage_locations == ["Australia"]:
            risk_level = "Low"
        elif storage_locations:
            risk_level = "Medium"
        else:
            risk_level = "Medium"

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
    return unique_values(value, allowed_values=COUNTRY_OPTIONS)


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
    return normalize_country_risk_assignments(APP_SETTINGS.get("country_risk_assignments", "{}"))


def get_country_risk_level(country_name):
    return get_country_risk_assignments().get(str(country_name).strip(), "")


def is_dark_mode_enabled():
    return str(APP_SETTINGS.get("dark_mode", "false")).strip().lower() == "true"


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
        if (record or {}).get("free_software"):
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


def build_assessment_pdf(record):
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
        textColor=colors.HexColor("#16324F"),
        alignment=TA_LEFT,
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#5B6773"),
        spaceAfter=12,
    )
    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.white,
        backColor=colors.HexColor("#1F4D6B"),
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
        textColor=colors.HexColor("#52616F"),
    )
    value_style = ParagraphStyle(
        "FieldValue",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#1F2933"),
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
            pdf_paragraph(format_assessment_value("risk_level", record.get("risk_level", ""), record), value_style),
            Paragraph("<b>Review Date</b>", label_style),
            pdf_paragraph(format_assessment_value("review_date", record.get("review_date", ""), record), value_style),
        ],
        [
            Paragraph("<b>Assessment Date</b>", label_style),
            pdf_paragraph(format_assessment_value("assessment_date", record.get("assessment_date", ""), record), value_style),
            Paragraph("<b>Next Audit Date</b>", label_style),
            pdf_paragraph(format_assessment_value("next_audit_date", record.get("next_audit_date", ""), record), value_style),
        ],
    ]
    summary_table = Table(summary_rows, colWidths=[34 * mm, 48 * mm, 34 * mm, 48 * mm], hAlign="LEFT")
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F6F8FB")),
                ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#D9E2EC")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D9E2EC")),
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

    for section_title, fields in PDF_SECTION_FIELDS:
        table_rows = []
        for field in fields:
            if field == "license_renewal_date" and record.get("license_type") == "Perpetual":
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
                    ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#D9E2EC")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.45, colors.HexColor("#E4EBF2")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
                ]
            )
        )
        story.append(section_table)
        story.append(Spacer(1, 8))

    signature_roles = ["IT Director", "Line Manager"]
    if record.get("allows_acceptance_on_behalf_of_entity"):
        signature_roles.append("Deputy Principal")

    story.append(Paragraph("Signatures", section_style))
    signature_rows = [
        [
            pdf_paragraph(role, label_style),
            Paragraph("Signature: ________________________________", value_style),
            Paragraph("Date: __________________", value_style),
        ]
        for role in signature_roles
    ]
    signature_table = Table(signature_rows, colWidths=[42 * mm, 88 * mm, 44 * mm], hAlign="LEFT")
    signature_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#D9E2EC")),
                ("INNERGRID", (0, 0), (-1, -1), 0.45, colors.HexColor("#E4EBF2")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
            ]
        )
    )
    story.append(signature_table)
    story.append(Spacer(1, 8))

    doc.build(story)
    buffer.seek(0)
    return buffer


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
}
SOFTWARE_ITEMS = []
SOFTWARE_ASSESSMENT_RECORDS = []
SOFTWARE_RECORDS = []
NEXT_SOFTWARE_ID = 1
NEXT_ASSESSMENT_ID = 1
VENDOR_RECORDS = []
VENDOR_ASSESSMENT_RECORDS = []
NEXT_VENDOR_ASSESSMENT_ID = 1
APP_SETTINGS = dict(DEFAULT_APP_SETTINGS)
RISK_CATEGORY_OPTIONS = (
    "Low",
    "Moderate",
    "High",
    "Very High",
)
RISK_CATEGORY_MAP_COLORS = {
    "Low": "#22c55e",
    "Moderate": "#facc15",
    "High": "#f97316",
    "Very High": "#dc2626",
}
DEFAULT_MAP_RISK_COLOR = "#2563eb"


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
    SOFTWARE_ITEMS.append(enrich_assessment(software))
    return next_id


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
                    json.dumps({key: record.get(key) for key in ASSESSMENT_FIELDS if key != "id"}),
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
                    json.dumps({key: record.get(key) for key in ASSESSMENT_FIELDS if key != "id"}),
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
            "vendor_privacy_policy_link": loaded_vendor.get("vendor_privacy_policy_link", ""),
            "online_support": loaded_vendor.get("online_support", ""),
            "vendor_audit_reminder_frequency": loaded_vendor.get("vendor_audit_reminder_frequency", "") or "1_year",
            "vendor_next_audit_date": loaded_vendor.get("vendor_next_audit_date", ""),
        }
        for field in ("vendor_security_assessment", *VENDOR_PRIVACY_FIELDS):
            if loaded_vendor.get(field):
                vendor[field] = loaded_vendor.get(field, "")
        vendors.append(vendor)
    return vendors


def persist_vendor_records():
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


def refresh_runtime_state():
    global SOFTWARE_ITEMS, SOFTWARE_ASSESSMENT_RECORDS, SOFTWARE_RECORDS, VENDOR_RECORDS, VENDOR_ASSESSMENT_RECORDS
    global APP_SETTINGS, NEXT_SOFTWARE_ID, NEXT_ASSESSMENT_ID, NEXT_VENDOR_ASSESSMENT_ID

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


def build_vendor_list():
    vendors_by_name = {}

    for record in build_software_catalog():
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
                "vendor_privacy_policy_link": record.get("vendor_privacy_policy_link", ""),
                "online_support": record.get("online_support", ""),
                "vendor_audit_reminder_frequency": record.get("vendor_audit_reminder_frequency", "") or "1_year",
                "vendor_next_audit_date": record.get("vendor_next_audit_date", ""),
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
        existing = vendors_by_name.setdefault(
            vendor_name,
            {
                "vendor_name": vendor_name,
                "vendor_country": vendor["vendor_country"],
                "vendor_website": vendor.get("vendor_website", ""),
                "vendor_terms_conditions_link": vendor.get("vendor_terms_conditions_link", ""),
                "vendor_privacy_policy_link": vendor.get("vendor_privacy_policy_link", ""),
                "online_support": vendor.get("online_support", ""),
                "vendor_audit_reminder_frequency": vendor.get("vendor_audit_reminder_frequency", "") or "1_year",
                "vendor_next_audit_date": vendor.get("vendor_next_audit_date", ""),
                "product_count": 0,
            },
        )
        existing["vendor_country"] = existing["vendor_country"] or vendor["vendor_country"]
        existing["vendor_website"] = existing["vendor_website"] or vendor.get("vendor_website", "")
        existing["vendor_terms_conditions_link"] = existing["vendor_terms_conditions_link"] or vendor.get("vendor_terms_conditions_link", "")
        existing["vendor_privacy_policy_link"] = existing["vendor_privacy_policy_link"] or vendor.get("vendor_privacy_policy_link", "")
        existing["online_support"] = existing["online_support"] or vendor.get("online_support", "")
        existing["vendor_audit_reminder_frequency"] = existing.get("vendor_audit_reminder_frequency") or vendor.get("vendor_audit_reminder_frequency", "") or "1_year"
        existing["vendor_next_audit_date"] = existing.get("vendor_next_audit_date") or vendor.get("vendor_next_audit_date", "")

    built_vendors = []
    for vendor_name in sorted(vendors_by_name):
        vendor = vendors_by_name[vendor_name]
        built_vendors.append(
            {
                "vendor_name": vendor["vendor_name"],
                "vendor_country": vendor["vendor_country"],
                "vendor_website": vendor.get("vendor_website", ""),
                "vendor_terms_conditions_link": vendor.get("vendor_terms_conditions_link", ""),
                "vendor_privacy_policy_link": vendor.get("vendor_privacy_policy_link", ""),
                "online_support": vendor.get("online_support", ""),
                "vendor_audit_reminder_frequency": vendor.get("vendor_audit_reminder_frequency", "") or "1_year",
                "vendor_next_audit_date": vendor.get("vendor_next_audit_date", ""),
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


def build_software_catalog():
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

    return sorted(latest_by_name.values(), key=lambda record: normalized_name(record.get("software_name", "")))


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

    linked_software = get_latest_software_record(software_name) or assessment_record
    next_audit_date = calculate_next_audit_date_from_assessment(
        assessment_record.get("assessment_date", ""),
        linked_software.get("audit_reminder_frequency", "") or assessment_record.get("audit_reminder_frequency", ""),
    )
    if not next_audit_date:
        return

    for record in SOFTWARE_RECORDS:
        if normalized_name(record.get("software_name", "")) == normalized:
            record["next_audit_date"] = next_audit_date
            record["review_date"] = next_audit_date
            record.update(enrich_assessment(record))


def update_software_details(original_software_name, updated_details):
    original_normalized = normalized_name(original_software_name)

    for record in SOFTWARE_RECORDS:
        if normalized_name(record.get("software_name", "")) == original_normalized:
            for field in SOFTWARE_DETAIL_FIELDS:
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

    if record.get("free_software"):
        record["currency_type"] = ""
        record["license_cost"] = ""

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
            "duplicates_existing",
            "genuine_need_notes",
            "product_security_assessment",
            "support_notes",
            "software_license_details",
            "license_renewal_date",
            "deployment_groups",
            "deployment_date",
            "audit_reminder_frequency",
            "vendor_security_assessment",
        ):
            if not record.get(field):
                record[field] = linked_software.get(field, "")
        for field in ("product_updates", "security_updates", "vendor_support"):
            if not record.get(field):
                record[field] = linked_software.get(field, False)

    record["software_id"] = record.get("software_id") or find_software_id(record.get("software_name", ""))
    record["assessment_date"] = form.get("assessment_date", "").strip() or determine_assessment_date(record)
    return enrich_assessment(record)


def collect_vendor_form_data(form):
    vendor_audit_reminder_frequency = form.get("vendor_audit_reminder_frequency", "").strip() or "1_year"
    vendor_next_audit_date = form.get("vendor_next_audit_date", "").strip()
    return {
        "vendor_name": form.get("vendor_name", "").strip(),
        "vendor_country": form.get("vendor_country", "").strip(),
        "vendor_website": form.get("vendor_website", "").strip(),
        "vendor_terms_conditions_link": form.get("vendor_terms_conditions_link", "").strip(),
        "vendor_privacy_policy_link": form.get("vendor_privacy_policy_link", "").strip(),
        "online_support": form.get("online_support", "").strip(),
        "vendor_audit_reminder_frequency": vendor_audit_reminder_frequency,
        "vendor_next_audit_date": vendor_next_audit_date,
    }


def blank_vendor():
    return {
        "vendor_name": "",
        "vendor_country": "",
        "vendor_website": "",
        "vendor_terms_conditions_link": "",
        "vendor_privacy_policy_link": "",
        "online_support": "",
        "vendor_audit_reminder_frequency": "1_year",
        "vendor_next_audit_date": "",
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
    assessment["data_processing_agreement_in_place"] = "data_processing_agreement_in_place" in form
    if assessment["cloud_hosted_data"] == "Yes":
        assessment["data_storage_location"] = (
            get_home_country()
            if assessment["data_processing_agreement_in_place"]
            else normalize_data_storage_locations(form.getlist("data_storage_location"))
        )
    else:
        assessment["data_processing_agreement_in_place"] = False
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

    if not updated_manual_vendor and not any(
        normalized_name(record["vendor_name"]) == normalized_name(updated_name) for record in SOFTWARE_RECORDS
    ):
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
                    "vendor_privacy_policy_link": existing_vendor.get("vendor_privacy_policy_link", ""),
                    "online_support": existing_vendor.get("online_support", ""),
                }
            )

    persist_software_records()
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
    software_catalog = build_software_catalog()
    risk_counts = Counter(record["risk_level"] for record in software_catalog if is_submitted_assessment(record))
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

    for vendor in build_vendor_list():
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
        vendor for vendor in build_vendor_list()
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
        "vendors": build_vendor_list(),
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

    for vendor in build_vendor_list():
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


def build_vendors_without_hosting_locations_report():
    vendors_without_locations = []

    for vendor in build_vendor_list():
        latest_assessment = get_latest_submitted_vendor_assessment(vendor.get("vendor_name", ""))
        if latest_assessment is None:
            continue

        locations = get_selected_values(latest_assessment.get("data_storage_location", ""))
        if locations:
            continue

        if latest_assessment.get("cloud_hosted_data") == "No":
            reason = "Cloud-hosted data marked as No"
        elif latest_assessment.get("data_processing_agreement_in_place"):
            reason = "No listed storage country recorded"
        else:
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


def build_vendor_data_storage_map(vendor_name):
    latest_assessment = get_latest_submitted_vendor_assessment(vendor_name)
    if latest_assessment is None:
        return {
            "has_audit": False,
            "has_locations": False,
            "locations": [],
            "map_locations": [],
            "vendor_assessment_date": "",
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

    return {
        "has_audit": True,
        "has_locations": bool(locations),
        "locations": locations,
        "map_locations": map_locations,
        "vendor_assessment_date": latest_assessment.get("vendor_assessment_date", ""),
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
    if get_latest_software_record(software_name) is None:
        return jsonify({"ok": False, "error": "Software not found"}), 404

    purchase_link = request.form.get("purchase_link", "").strip()
    save_software_purchase_link(software_name, purchase_link)
    return jsonify({"ok": True, "purchase_link": purchase_link})


@app.route("/software")
def software_list():
    return render_template("software_list.html", software_records=build_software_catalog())


@app.route("/reports")
def reports():
    return render_template(
        "reports.html",
        data_hosting_heatmap=build_data_hosting_heatmap(),
        vendors_without_hosting_locations=build_vendors_without_hosting_locations_report(),
    )


@app.route("/software/new", methods=["GET", "POST"])
def new_software():
    global NEXT_SOFTWARE_ID

    if request.method == "POST":
        software_details = collect_software_form_data(request.form)
        if software_details["software_name"] and software_details["vendor_name"]:
            record = blank_assessment()
            for field in SOFTWARE_DETAIL_FIELDS:
                if field in software_details:
                    record[field] = software_details[field]
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

    return render_template(
        "software_edit.html",
        software=blank_assessment(),
        form_title="Add Software",
        submit_label="Save Software",
        is_new=True,
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
            return redirect(url_for("software_detail", software_name=updated_details["software_name"]))

    return render_template(
        "software_edit.html",
        software=software_record,
        form_title="Edit Software",
        submit_label="Update Software",
        is_new=False,
        **FORM_OPTION_CONTEXT,
    )


@app.route("/software/<path:software_name>/delete", methods=["POST"])
def delete_software(software_name):
    assessments = get_software_history(software_name)
    if not assessments:
        abort(404)

    delete_software_details(software_name)
    return redirect(url_for("software_list"))


@app.route("/software/<path:software_name>")
def software_detail(software_name):
    software_record = get_latest_software_record(software_name)
    if not software_record:
        abort(404)
    assessments = get_software_assessment_records(software_name)

    return render_template(
        "software_detail.html",
        software=software_record,
        software_name=software_record["software_name"],
        assessments=assessments,
    )


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
        submit_label="Save Vendor Audit",
        **FORM_OPTION_CONTEXT,
    )


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

    assessment = collect_vendor_assessment_form_data(request.form, NEXT_VENDOR_ASSESSMENT_ID)
    assessment["vendor_name"] = vendor["vendor_name"]
    VENDOR_ASSESSMENT_RECORDS.append(assessment)
    sync_vendor_schedule_from_assessment(assessment)
    persist_vendor_assessment_records()
    NEXT_VENDOR_ASSESSMENT_ID += 1
    return redirect(url_for("vendor_detail", vendor_name=vendor["vendor_name"]))


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
        persist_app_settings()
        saved = True

    return render_template(
        "settings.html",
        settings=APP_SETTINGS,
        saved=saved,
        country_options=COUNTRY_OPTIONS,
        risk_category_options=RISK_CATEGORY_OPTIONS,
        country_risk_assignments=get_country_risk_assignments(),
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
        return redirect(url_for("vendor_list"))

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
        form_data = enrich_assessment(form_data)
        existing_record = get_assessment_or_none(assessment_id) if assessment_id is not None else None
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
        return redirect(url_for("software_detail", software_name=form_data["software_name"]))

    draft_id = request.args.get("draft_id", type=int)
    source_assessment_id = request.args.get("source_assessment_id", type=int)
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
                form_title="New Software Assessment",
                submit_label="Submit Assessment",
                is_edit=False,
                software_details_editable=True,
                autosave_enabled=True,
                **FORM_OPTION_CONTEXT,
            )

    source_assessment = get_software_record_or_none(source_assessment_id) if source_assessment_id is not None else None
    draft_record = build_prefilled_assessment(source_assessment)
    draft_record["id"] = NEXT_ASSESSMENT_ID
    draft_record["is_assessment"] = True
    draft_record["submission_status"] = "draft"
    draft_record["assessment_date"] = date.today().isoformat()
    enriched_draft = enrich_assessment(draft_record)
    SOFTWARE_RECORDS.append(enriched_draft)
    persist_software_records()
    NEXT_ASSESSMENT_ID += 1
    return redirect(
        url_for(
            "new_assessment",
            draft_id=enriched_draft["id"],
            source_assessment_id=source_assessment_id,
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
        return redirect(url_for("software_detail", software_name=updated_record["software_name"]))

    return render_template(
        "assessment_form.html",
        assessment=record,
        assessment_id=assessment_id,
        assessment_date=record.get("assessment_date", ""),
        software_purchase_link=get_software_purchase_link_for_record(record),
        vendor_terms_conditions_link=get_vendor_terms_link_for_record(record),
        vendor_privacy_policy_link=get_vendor_privacy_policy_link_for_record(record),
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
    draft_record["is_assessment"] = True
    draft_record["submission_status"] = "draft"
    index = SOFTWARE_RECORDS.index(record)
    SOFTWARE_RECORDS[index] = draft_record
    sync_vendor_from_assessment(draft_record)
    persist_software_records()
    persist_vendor_records()
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
    pdf_record["vendor_privacy_policy_link"] = (
        record.get("vendor_privacy_policy_link") or get_vendor_privacy_policy_link_for_record(record)
    )
    pdf_record["purchase_link"] = record.get("purchase_link") or get_software_purchase_link_for_record(record)
    vendor = get_latest_vendor_assessment(record.get("vendor_name", "")) or {}
    for field in VENDOR_PRIVACY_FIELDS:
        pdf_record[field] = vendor.get(field, "")
    pdf_record["vendor_security_assessment"] = vendor.get(
        "vendor_security_assessment",
        record.get("vendor_security_assessment", ""),
    )
    safe_name = (record.get("software_name") or f"assessment-{assessment_id}").strip().replace(" ", "-")
    audit_date = (
        record.get("assessment_date")
        or record.get("review_date")
        or record.get("next_audit_date")
        or f"assessment-{assessment_id}"
    )
    pdf_data = build_assessment_pdf(pdf_record)
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
