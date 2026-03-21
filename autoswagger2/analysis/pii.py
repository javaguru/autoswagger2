# autoswagger2/analysis/pii.py
# Manages PII detection using Presidio.

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, Pattern, PatternRecognizer
from presidio_analyzer.context_aware_enhancers import LemmaContextAwareEnhancer
import json

class PiiAnalyzer:
    def __init__(self):
        registry = RecognizerRegistry()
        self._setup_recognizers(registry)

        context_aware_enhancer = LemmaContextAwareEnhancer(
            context_similarity_factor=0.35,
            min_score_with_context_similarity=0.4
        )

        self.analyzer = AnalyzerEngine(
            registry=registry,
            context_aware_enhancer=context_aware_enhancer
        )
        self.supported_entities = [
            "PERSON","EMAIL_ADDRESS","PHONE_NUMBER","ADDRESS",
            "CREDIT_CARD_NUMBER", "DATE_OF_BIRTH", "FR_INSEE_NUMBER",
            "US_SSN", "PASSPORT_NUMBER", "IBAN_NUMBER", "FR_LICENSE_PLATE",
            "IP_ADDRESS", "MAC_ADDRESS", "US_LICENSE_PLATE"
        ]

    def _setup_recognizers(self, registry):
        # Person
        person_pattern = Pattern(name="person", regex=r"\b[A-Z][a-z]+\s[A-Z][a-z]+\b", score=0.85)
        person_recognizer = PatternRecognizer(supported_entity="PERSON", patterns=[person_pattern], context=["name", "first_name", "last_name", "firstname", "lastname"])
        registry.add_recognizer(person_recognizer)

        # Phone Number
        phone_pattern = Pattern(name="phone_number", regex=r"(\+?\d{1,3}[-.\s]?(\d{3})[-.\s]?(\d{3,4})[-.\s]?(\d{4}))", score=0.85)
        phone_recognizer = PatternRecognizer(supported_entity="PHONE_NUMBER", patterns=[phone_pattern], context=["phone", "mobile", "telephone", "tel", "phone_number"])
        registry.add_recognizer(phone_recognizer)

        # Email Address
        email_pattern = Pattern(name="email", regex=r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", score=0.85)
        email_recognizer = PatternRecognizer(supported_entity="EMAIL_ADDRESS", patterns=[email_pattern], context=["email", "email_address", "contact"])
        registry.add_recognizer(email_recognizer)

        # Address (Improved Context)
        address_pattern = Pattern(name="address", regex=r"\b\d{1,5}\s\w+\s\w+\b", score=0.85)
        address_recognizer = PatternRecognizer(supported_entity="ADDRESS", patterns=[address_pattern], context=["addr", "address", "location", "street", "rue", "avenue", "boulevard", "city", "ville", "zipcode", "postcode", "code postal", "country", "pays"])
        registry.add_recognizer(address_recognizer)

        # Credit Card Number
        cc_pattern = Pattern(name="credit_card", regex=r"\b(?:\d[ -]*?){13,16}\b", score=0.85)
        cc_recognizer = PatternRecognizer(supported_entity="CREDIT_CARD_NUMBER", patterns=[cc_pattern], context=["card", "cc", "credit", "debit", "cardnumber", "pan", "carte"])
        registry.add_recognizer(cc_recognizer)

        # Date of Birth
        dob_pattern = Pattern(name="date_of_birth", regex=r"\b(\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2})\b", score=0.85)
        dob_recognizer = PatternRecognizer(supported_entity="DATE_OF_BIRTH", patterns=[dob_pattern], context=["dob", "birthdate", "date_of_birth", "birthday", "naissance"])
        registry.add_recognizer(dob_recognizer)

        # French INSEE Number
        insee_pattern = Pattern(name="fr_insee_number", regex=r"\b[12]\d{2}(0[1-9]|1[0-2])(2[ABab]|\d{2})\d{3}\d{3}\d{2}\b", score=0.9)
        insee_recognizer = PatternRecognizer(supported_entity="FR_INSEE_NUMBER", patterns=[insee_pattern], context=["insee", "nir", "securite_sociale", "numéro de sécurité sociale"])
        registry.add_recognizer(insee_recognizer)

        # US Social Security Number
        ssn_pattern = Pattern(name="us_ssn", regex=r"\b\d{3}-\d{2}-\d{4}\b", score=0.9)
        ssn_recognizer = PatternRecognizer(supported_entity="US_SSN", patterns=[ssn_pattern], context=["ssn", "social security number", "taxpayer id"])
        registry.add_recognizer(ssn_recognizer)

        # Passport Number
        passport_pattern = Pattern(name="passport_number", regex=r"\b[A-Z0-9<]{8,15}\b", score=0.8)
        passport_recognizer = PatternRecognizer(supported_entity="PASSPORT_NUMBER", patterns=[passport_pattern], context=["passport", "passeport", "passport_number", "passportno", "travel document"])
        registry.add_recognizer(passport_recognizer)

        # IBAN Number
        iban_pattern = Pattern(name="iban", regex=r"\b[A-Z]{2}[0-9]{2}(?:[ ]?[0-9]{4}){4,7}\b", score=0.85)
        iban_recognizer = PatternRecognizer(supported_entity="IBAN_NUMBER", patterns=[iban_pattern], context=["iban", "bank", "account", "rib", "compte"])
        registry.add_recognizer(iban_recognizer)

        # French License Plate
        fr_plate_pattern = Pattern(name="fr_license_plate", regex=r"\b([A-Z]{2}-\d{3}-[A-Z]{2}|\d{1,4}\s[A-Z]{2,3}\s\d{2})\b", score=0.7)
        fr_plate_recognizer = PatternRecognizer(supported_entity="FR_LICENSE_PLATE", patterns=[fr_plate_pattern], context=["immatriculation", "plaque", "license_plate", "vehicle", "registration"])
        registry.add_recognizer(fr_plate_recognizer)

        # US License Plate
        us_plate_pattern = Pattern(name="us_license_plate", regex=r"\b([A-Z]{1,3}[- ]?\d{1,4}|\d{1,4}[- ]?[A-Z]{1,3})\b", score=0.75)
        us_plate_recognizer = PatternRecognizer(supported_entity="US_LICENSE_PLATE", patterns=[us_plate_pattern], context=["license", "plate", "vehicle", "registration", "vin"])
        registry.add_recognizer(us_plate_recognizer)

        # IP Address
        ip_pattern = Pattern(name="ip_address", regex=r"\b(?:\d{1,3}\.){3}\d{1,3}\b", score=0.7)
        ip_recognizer = PatternRecognizer(supported_entity="IP_ADDRESS", patterns=[ip_pattern], context=["ip", "address", "ip_address", "last_login_ip"])
        registry.add_recognizer(ip_recognizer)

        # MAC Address
        mac_pattern = Pattern(name="mac_address", regex=r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b", score=0.8)
        mac_recognizer = PatternRecognizer(supported_entity="MAC_ADDRESS", patterns=[mac_pattern], context=["mac", "mac_address", "physical_address"])
        registry.add_recognizer(mac_recognizer)

    def analyze_content(self, content_text):
        pii_detected = False
        pii_data = {}

        try:
            # Analyze the full text for any PII type, regardless of format
            pres_res = self.analyzer.analyze(
                text=content_text,
                entities=self.supported_entities,
                language='en'
            )

            if pres_res:
                pii_detected = True
                for ent in pres_res:
                    pii_data.setdefault(ent.entity_type, {'values': set(), 'detection_methods': set()})['values'].add(content_text[ent.start:ent.end])
                    pii_data[ent.entity_type]['detection_methods'].add('presidio')

        except Exception:
            # Presidio might fail on some inputs, we can ignore it and return no findings.
            pass

        return pii_detected, pii_data
