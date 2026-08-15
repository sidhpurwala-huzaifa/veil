"""Mapping between REDACT's 51 entity types and veil's detector types.

Only entity types that veil's Tier 1 (regex) detectors can plausibly detect
are mapped.  Everything else is tracked as ``unmapped`` so the report can
show which REDACT categories veil does not cover — that's the gap Tier 2/3
detectors are meant to fill.
"""

from __future__ import annotations

# REDACT type -> veil entity_type (or None if unmapped).
# Names taken from the actual REDACT sample data (51 types).
REDACT_TO_VEIL: dict[str, str | None] = {
    # -- Email (two REDACT variants) ---------------------------------------
    "Work_Email_Address":           "EMAIL",
    "Personal_Email_Address":       "EMAIL",

    # -- Phone (two REDACT variants) ---------------------------------------
    "Telephone_Numbers_Personal":   "PHONE",
    "Telephone_Numbers_Work":       "PHONE",

    # -- Network -----------------------------------------------------------
    "Static_IP_Address":            "IP_ADDRESS",

    # -- Financial ---------------------------------------------------------
    "Credit_Card_Numbers":          "CREDIT_CARD",

    # -- Identification ----------------------------------------------------
    "Date_of_Birth":                "DATE_OF_BIRTH",
    "Passport_Number":              "PASSPORT_US",
    "Tax_Reference_Number":         "US_ITIN",
    "Password":                     "GENERIC_SECRET",

    # -- All unmapped types (Tier 2/3 territory) ---------------------------
    "Full_Name":                    None,
    "Last_Family_Name":             None,
    "First_Given_Name":             None,
    "Customer_Reference_Number":    None,
    "Date_Time":                    None,
    "Org_Name":                     None,
    "City":                         None,
    "National_Identification_Number": None,
    "Employee_ID_Number":           None,
    "Business_Title":               None,
    "Address_Personal":             None,
    "Medical_Information":          None,
    "Compensation_and_Salary":      None,
    "Nationality":                  None,
    "Address_Work":                 None,
    "Social_Media_Identifiers":     None,
    "Gender":                       None,
    "Marital_Status":               None,
    "Location":                     None,
    "Age":                          None,
    "Crime":                        None,
    "State":                        None,
    "Preferred_Name":               None,
    "Allergy_Information":          None,
    "Account_Statements":           None,
    "Religion":                     None,
    "Sex_Orientation":              None,
    "Citizenship_Status":           None,
    "Geolocation_Data":             None,
    "PEP_Status":                   None,
    "Political_Party":              None,
    "Building_Badge_Card_Number":   None,
    "Driving_License_Number":       None,
    "Place_of_Birth":               None,
    "Performance_Assessment":       None,
    "Sickness_Day_Records":         None,
    "Trade_Union_Membership":       None,
    "Professional_Background":      None,
    "Country_of_Residence":         None,
    "Emergency_Contact_Details":    None,
    "Disciplinary_Action":          None,
}

MAPPED_REDACT_TYPES: set[str] = {k for k, v in REDACT_TO_VEIL.items() if v is not None}
UNMAPPED_REDACT_TYPES: set[str] = {k for k, v in REDACT_TO_VEIL.items() if v is None}

MAPPED_VEIL_TYPES: set[str] = {v for v in REDACT_TO_VEIL.values() if v is not None}


def redact_to_veil(redact_type: str) -> str | None:
    """Map a REDACT entity type to its veil equivalent, or None."""
    return REDACT_TO_VEIL.get(redact_type)
