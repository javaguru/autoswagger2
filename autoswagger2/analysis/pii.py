# autoswagger2/analysis/pii.py
# Manages PII detection using Presidio.

import re
import threading
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, Pattern, PatternRecognizer
from presidio_analyzer.context_aware_enhancers import LemmaContextAwareEnhancer


class PiiAnalyzer:
    _shared_analyzer = None
    _init_lock = threading.Lock()
    _analyze_lock = threading.Lock()
    DEFAULT_SUPPORTED_ENTITIES = [
        "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "ADDRESS",
        "CREDIT_CARD_NUMBER", "DATE_OF_BIRTH", "FR_INSEE_NUMBER",
        "US_SSN", "PASSPORT_NUMBER", "IBAN_NUMBER", "FR_LICENSE_PLATE",
        "IP_ADDRESS", "MAC_ADDRESS", "US_LICENSE_PLATE",
    ]
    CONTEXT_KEYWORDS = {
        "PASSPORT_NUMBER": {"passport", "passeport", "passportno", "mrz", "travel", "document"},
        "US_LICENSE_PLATE": {
            "plate", "plaque", "license", "licence", "immatriculation",
            "vehicle", "vehicule", "car", "auto", "vin", "registration",
        },
        "FR_LICENSE_PLATE": {
            "plate", "plaque", "license", "licence", "immatriculation",
            "vehicle", "vehicule", "car", "auto", "registration",
        },
        "PHONE_NUMBER": {"phone", "mobile", "telephone", "tel", "cell", "fax", "contact"},
        "CREDIT_CARD_NUMBER": {"card", "cc", "credit", "debit", "cardnumber", "pan", "carte"},
        "DATE_OF_BIRTH": {"dob", "birthdate", "birth", "birthday", "naissance"},
    }
    NON_PERSON_WORDS = {
        "street", "st", "avenue", "ave", "boulevard", "blvd", "road", "rd", "lane", "ln",
        "drive", "dr", "court", "ct", "place", "way", "rue", "square", "park", "city",
        "product", "name", "user", "username", "first", "last", "full", "item", "test",
        "sample", "example", "dummy", "mock", "default", "admin", "account", "customer",
        "client", "service", "server", "internal", "external", "error", "bad", "not",
        "found", "gateway", "status", "code", "content", "type", "bearer", "token",
        "api", "key", "secret", "access", "data", "info", "value", "null", "true",
        "false", "credit", "card", "bank", "license", "plate", "social", "security",
        "passport", "date", "birth", "phone", "number", "email", "address", "public",
        "private", "system", "config", "method", "allowed", "hello", "world", "lorem", "ipsum",
    }
    ENTITY_PRIORITY = {
        entity: idx for idx, entity in enumerate([
            "CREDIT_CARD_NUMBER",
            "IBAN_NUMBER",
            "FR_INSEE_NUMBER",
            "US_SSN",
            "EMAIL_ADDRESS",
            "MAC_ADDRESS",
            "IP_ADDRESS",
            "FR_LICENSE_PLATE",
            "PASSPORT_NUMBER",
            "PHONE_NUMBER",
            "ADDRESS",
            "DATE_OF_BIRTH",
            "US_LICENSE_PLATE",
            "PERSON",
        ])
    }

    def __init__(self):
        self._analyzer = None
        self.supported_entities = list(self.DEFAULT_SUPPORTED_ENTITIES)

    @property
    def analyzer(self):
        if self._analyzer is not None:
            return self._analyzer
        return self._get_shared_analyzer()

    @analyzer.setter
    def analyzer(self, value):
        self._analyzer = value

    @classmethod
    def _get_shared_analyzer(cls):
        if cls._shared_analyzer is None:
            with cls._init_lock:
                if cls._shared_analyzer is None:
                    registry = RecognizerRegistry()
                    cls._setup_recognizers(registry)
                    context_aware_enhancer = LemmaContextAwareEnhancer(
                        context_similarity_factor=0.35,
                        min_score_with_context_similarity=0.4,
                    )
                    cls._shared_analyzer = AnalyzerEngine(
                        registry=registry,
                        context_aware_enhancer=context_aware_enhancer,
                    )
        return cls._shared_analyzer

    @classmethod
    def _setup_recognizers(cls, registry):
        # Person (strict Title Case two-word names; generic terms filtered post-match)
        person_pattern = Pattern(name="person", regex=r"(?-i:\b[A-Z][a-z]{1,20}\s[A-Z][a-z]{1,20}\b)", score=0.85)
        person_recognizer = PatternRecognizer(supported_entity="PERSON", patterns=[person_pattern], context=["name", "first_name", "last_name", "firstname", "lastname"])
        registry.add_recognizer(person_recognizer)

        # Phone Number (international/parenthesized high confidence; national requires context)
        phone_intl_pattern = Pattern(
            name="phone_intl",
            regex=r"(?<![\d+\-.])(?:\+\d{1,3}[-.\s]?(?:\(?\d{1,4}\)?[-.\s]?){2,4}\d{2,4}|\(\d{3}\)\s?\d{3}[-.\s]\d{4})(?![\d.\-])",
            score=0.85,
        )
        phone_local_pattern = Pattern(
            name="phone_local",
            regex=r"(?<![\d+\-.])(?:\d{3}[-.\s]\d{3}[-.\s]\d{4}|0[1-9](?:[-.\s]\d{2}){4})(?![\d.\-])",
            score=0.45,
        )
        phone_recognizer = PatternRecognizer(supported_entity="PHONE_NUMBER", patterns=[phone_intl_pattern, phone_local_pattern], context=["phone", "mobile", "telephone", "tel", "phone_number"])
        registry.add_recognizer(phone_recognizer)

        # Email Address
        email_pattern = Pattern(name="email", regex=r"(?<![A-Za-z0-9_.+-])[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}(?![A-Za-z0-9_.-])", score=0.85)
        email_recognizer = PatternRecognizer(supported_entity="EMAIL_ADDRESS", patterns=[email_pattern], context=["email", "email_address", "contact"])
        registry.add_recognizer(email_recognizer)

        # Address (explicit street suffixes to avoid colliding with grouped numbers/cards)
        address_en_pattern = Pattern(
            name="address_en",
            regex=r"(?-i:\b\d{1,5}\s+(?:[A-ZÀ-Ý][A-Za-zÀ-ÿ'-]*\s+){1,3}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Way|Rue|Chemin|Impasse|Allée|Allee|Cours|Quai)\b)",
            score=0.85,
        )
        address_fr_pattern = Pattern(
            name="address_fr",
            regex=r"(?i:\b\d{1,5}\s+(?:bis\s+|ter\s+)?(?:rue|avenue|boulevard|chemin|impasse|allée|allee|place|quai)\s+[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ\s'-]{2,40}\b)",
            score=0.85,
        )
        address_recognizer = PatternRecognizer(supported_entity="ADDRESS", patterns=[address_en_pattern, address_fr_pattern], context=["addr", "address", "location", "street", "rue", "avenue", "boulevard", "city", "ville", "zipcode", "postcode", "code postal", "country", "pays"])
        registry.add_recognizer(address_recognizer)

        # Credit Card Number (grouped 4-digit blocks high confidence; bare 13-19 digits require context)
        cc_grouped_pattern = Pattern(name="credit_card_grouped", regex=r"(?<![\d.\-])\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,4}(?![\d.\-])", score=0.85)
        cc_plain_pattern = Pattern(name="credit_card_plain", regex=r"(?<![\d.\-])\d{13,19}(?![\d.\-])", score=0.45)
        cc_recognizer = PatternRecognizer(supported_entity="CREDIT_CARD_NUMBER", patterns=[cc_grouped_pattern, cc_plain_pattern], context=["card", "cc", "credit", "debit", "cardnumber", "pan", "carte"])
        registry.add_recognizer(cc_recognizer)

        # Date of Birth (requires birth/dob context to avoid flagging technical ISO timestamps)
        dob_pattern = Pattern(name="date_of_birth", regex=r"(?<![\d/\-])(?:\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2})(?![\d/\-T])", score=0.45)
        dob_recognizer = PatternRecognizer(supported_entity="DATE_OF_BIRTH", patterns=[dob_pattern], context=["dob", "birthdate", "date_of_birth", "birthday", "naissance"])
        registry.add_recognizer(dob_recognizer)

        # French INSEE Number
        insee_pattern = Pattern(name="fr_insee_number", regex=r"(?<!\d)[12]\d{2}(?:0[1-9]|1[0-2])(?:2[ABab]|\d{2})\d{3}\d{3}\d{2}(?!\d)", score=0.9)
        insee_recognizer = PatternRecognizer(supported_entity="FR_INSEE_NUMBER", patterns=[insee_pattern], context=["insee", "nir", "securite_sociale", "numéro de sécurité sociale"])
        registry.add_recognizer(insee_recognizer)

        # US Social Security Number
        ssn_pattern = Pattern(name="us_ssn", regex=r"(?<![\d\-])\d{3}-\d{2}-\d{4}(?![\d\-])", score=0.9)
        ssn_recognizer = PatternRecognizer(supported_entity="US_SSN", patterns=[ssn_pattern], context=["ssn", "social security number", "taxpayer id"])
        registry.add_recognizer(ssn_recognizer)

        # Passport Number (case-sensitive MRZ auto-sufficient; alphanumeric requires digits + context)
        passport_mrz_pattern = Pattern(name="passport_mrz", regex=r"(?-i:(?<![A-Za-z0-9_\-.=/])[A-Z0-9]{5,12}<<[A-Z0-9<]{2,20}(?![A-Za-z0-9_\-.=/]))", score=0.9)
        passport_alnum_pattern = Pattern(name="passport_alnum", regex=r"(?-i:(?<![A-Za-z0-9_\-.=/])(?=[A-Z0-9]{6,12}(?![A-Za-z0-9_\-.=/]))(?=.*[A-Z])(?=.*\d)[A-Z0-9]+)", score=0.45)
        passport_recognizer = PatternRecognizer(supported_entity="PASSPORT_NUMBER", patterns=[passport_mrz_pattern, passport_alnum_pattern], context=["passport", "passeport", "passport_number", "passportno", "travel document"])
        registry.add_recognizer(passport_recognizer)

        # IBAN Number
        iban_pattern = Pattern(name="iban", regex=r"(?-i:(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,3})?(?![A-Za-z0-9]))", score=0.85)
        iban_recognizer = PatternRecognizer(supported_entity="IBAN_NUMBER", patterns=[iban_pattern], context=["iban", "bank", "account", "rib", "compte"])
        registry.add_recognizer(iban_recognizer)

        # French License Plate (SIV unambiguous; FNI requires context)
        fr_siv_pattern = Pattern(name="fr_license_plate_siv", regex=r"(?-i:(?<![A-Za-z0-9_\-.:/=])[A-Z]{2}-\d{3}-[A-Z]{2}(?![A-Za-z0-9_\-.:/=]))", score=0.85)
        fr_fni_pattern = Pattern(name="fr_license_plate_fni", regex=r"(?-i:(?<![A-Za-z0-9_\-.:/=])\d{1,4}\s[A-Z]{2,3}\s\d{2}(?![A-Za-z0-9_\-.:/=]))", score=0.45)
        fr_plate_recognizer = PatternRecognizer(supported_entity="FR_LICENSE_PLATE", patterns=[fr_siv_pattern, fr_fni_pattern], context=["immatriculation", "plaque", "license_plate", "vehicle", "registration"])
        registry.add_recognizer(fr_plate_recognizer)

        # US License Plate (uppercase bounded; requires vehicle/plate context)
        us_plate_pattern = Pattern(name="us_license_plate", regex=r"(?-i:(?<![A-Za-z0-9_\-.:/=])(?:[A-Z]{2,3}[- ]\d{3,4}|\d{1,4}[- ][A-Z]{2,3})(?![A-Za-z0-9_\-.:/=]))", score=0.45)
        us_plate_recognizer = PatternRecognizer(supported_entity="US_LICENSE_PLATE", patterns=[us_plate_pattern], context=["license", "plate", "vehicle", "registration", "vin"])
        registry.add_recognizer(us_plate_recognizer)

        # IP Address (valid IPv4 octets 0..255)
        ip_pattern = Pattern(name="ip_address", regex=r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])", score=0.8)
        ip_recognizer = PatternRecognizer(supported_entity="IP_ADDRESS", patterns=[ip_pattern], context=["ip", "address", "ip_address", "last_login_ip"])
        registry.add_recognizer(ip_recognizer)

        # MAC Address
        mac_pattern = Pattern(name="mac_address", regex=r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])", score=0.85)
        mac_recognizer = PatternRecognizer(supported_entity="MAC_ADDRESS", patterns=[mac_pattern], context=["mac", "mac_address", "physical_address"])
        registry.add_recognizer(mac_recognizer)

    @classmethod
    def _entity_rank(cls, entity_type):
        return cls.ENTITY_PRIORITY.get(entity_type, len(cls.ENTITY_PRIORITY))

    @classmethod
    def _has_nearby_context(cls, text, start, end, keywords, window=80):
        before = text[max(0, start - window):start]
        after = text[end:min(len(text), end + window)]
        snippet = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", f"{before} {after}")
        tokens = set(re.findall(r"[a-z0-9à-ÿ]+", snippet.lower()))
        return bool(tokens & keywords)

    @classmethod
    def _filter_and_dedupe_results(cls, content_text, pres_res):
        filtered = []
        for ent in pres_res:
            matched_val = content_text[ent.start:ent.end]
            raw_score = getattr(ent, "score", 0.85)
            score = float(raw_score) if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool) else 0.85

            if ent.entity_type == "PERSON":
                words = re.findall(r"[a-zà-ÿ]+", matched_val.lower())
                if not words or any(word in cls.NON_PERSON_WORDS for word in words):
                    continue

            needs_context = (
                (ent.entity_type in ("PASSPORT_NUMBER", "US_LICENSE_PLATE") and "<<" not in matched_val)
                or score < 0.6
            )
            if needs_context:
                keywords = cls.CONTEXT_KEYWORDS.get(ent.entity_type)
                if not keywords or not cls._has_nearby_context(content_text, ent.start, ent.end, keywords):
                    continue

            filtered.append((ent, score))

        filtered.sort(key=lambda item: (-(item[0].end - item[0].start), cls._entity_rank(item[0].entity_type), -item[1], item[0].start))

        kept = []
        for ent, _ in filtered:
            if any(max(ent.start, prev.start) < min(ent.end, prev.end) for prev in kept):
                continue
            kept.append(ent)
        return kept

    def analyze_content(self, content_text):
        pii_detected = False
        pii_data = {}

        if not isinstance(content_text, str) or not content_text.strip():
            return pii_detected, pii_data

        try:
            # Analyze the full text for any PII type, regardless of format
            with self._analyze_lock:
                pres_res = self.analyzer.analyze(
                    text=content_text,
                    entities=self.supported_entities,
                    language='en',
                )

            cleaned_res = self._filter_and_dedupe_results(content_text, pres_res) if pres_res else []
            if cleaned_res:
                pii_detected = True
                for ent in cleaned_res:
                    pii_data.setdefault(ent.entity_type, {'values': set(), 'detection_methods': set()})['values'].add(content_text[ent.start:ent.end])
                    pii_data[ent.entity_type]['detection_methods'].add('presidio')

        except Exception:
            # Presidio might fail on some inputs, we can ignore it and return no findings.
            pass

        return pii_detected, pii_data
