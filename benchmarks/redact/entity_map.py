"""Mapping between REDACT's 51 entity types and veil's detector types.

Tier 1 (regex) and Tier 2 (NER) detectors are both represented here.
Types that neither tier can plausibly detect are tracked as ``unmapped``
so the report shows the remaining gap for Tier 3 (LLM classifier).
"""

from __future__ import annotations

# REDACT type -> veil entity_type (or None if unmapped).
# Names taken from the actual REDACT sample data (51 types).
REDACT_TO_VEIL: dict[str, str | None] = {
    # ── Tier 1 (regex) ────────────────────────────────────────────────────
    "Work_Email_Address":           "EMAIL",
    "Personal_Email_Address":       "EMAIL",
    "Telephone_Numbers_Personal":   "PHONE",
    "Telephone_Numbers_Work":       "PHONE",
    "Static_IP_Address":            "IP_ADDRESS",
    "Credit_Card_Numbers":          "CREDIT_CARD",
    "Date_of_Birth":                "DATE_OF_BIRTH",
    "Passport_Number":              "PASSPORT",
    "Tax_Reference_Number":         "US_ITIN",
    "Password":                     "GENERIC_SECRET",

    # ── Tier 2 (NER — PERSON_NAME) ───────────────────────────────────────
    "Full_Name":                    "PERSON_NAME",
    "Last_Family_Name":             "PERSON_NAME",
    "First_Given_Name":             "PERSON_NAME",
    "Preferred_Name":               "PERSON_NAME",
    "Emergency_Contact_Details":    "PERSON_NAME",

    # ── Tier 2 (NER — ORGANIZATION) ──────────────────────────────────────
    "Org_Name":                     "ORGANIZATION",

    # ── Tier 2 (NER — LOCATION) ──────────────────────────────────────────
    "City":                         "LOCATION",
    "State":                        "LOCATION",
    "Location":                     "LOCATION",
    "Country_of_Residence":         "LOCATION",
    "Place_of_Birth":               "LOCATION",
    "Address_Personal":             "LOCATION",
    "Address_Work":                 "LOCATION",
    "Geolocation_Data":             "LOCATION",

    # ── Tier 2 (NER — DATE_TIME) ─────────────────────────────────────────
    "Date_Time":                    "DATE_TIME",

    # ── Tier 2 (NER — NORP_GROUP) ────────────────────────────────────────
    "Nationality":                  "NORP_GROUP",
    "Religion":                     "NORP_GROUP",
    "Political_Party":              "NORP_GROUP",
    "Citizenship_Status":           "NORP_GROUP",
    "Trade_Union_Membership":       "NORP_GROUP",

    # ── Unmapped (Tier 3 / LLM classifier territory) ─────────────────────
    "Customer_Reference_Number":    None,
    "National_Identification_Number": None,
    "Employee_ID_Number":           None,
    "Business_Title":               None,
    "Medical_Information":          None,
    "Compensation_and_Salary":      None,
    "Social_Media_Identifiers":     None,
    "Gender":                       None,
    "Marital_Status":               None,
    "Age":                          None,
    "Crime":                        None,
    "Allergy_Information":          None,
    "Account_Statements":           None,
    "Sex_Orientation":              None,
    "PEP_Status":                   None,
    "Building_Badge_Card_Number":   None,
    "Driving_License_Number":       None,
    "Performance_Assessment":       None,
    "Sickness_Day_Records":         None,
    "Professional_Background":      None,
    "Disciplinary_Action":          None,
}

MAPPED_REDACT_TYPES: set[str] = {k for k, v in REDACT_TO_VEIL.items() if v is not None}
UNMAPPED_REDACT_TYPES: set[str] = {k for k, v in REDACT_TO_VEIL.items() if v is None}

MAPPED_VEIL_TYPES: set[str] = {v for v in REDACT_TO_VEIL.values() if v is not None}


def redact_to_veil(redact_type: str) -> str | None:
    """Map a REDACT entity type to its veil equivalent, or None."""
    return REDACT_TO_VEIL.get(redact_type)
