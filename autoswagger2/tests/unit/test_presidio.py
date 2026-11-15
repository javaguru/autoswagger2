# tests/unit/test_presidio.py
import json
from autoswagger2.analysis.pii import PiiAnalyzer
from autoswagger2.utils.validators import ResultValidator


def test_presidio_no_false_positives_on_mock_products():
    analyzer = PiiAnalyzer()
    content = json.dumps(
        [{"productId": "prod-0", "name": "Product Name 0", "price": 19.99}],
        separators=(",", ":"),
    )
    detected, data = analyzer.analyze_content(content)
    assert detected is False
    assert data == {}


def test_presidio_no_false_positives_on_proxy_headers_and_timestamps():
    analyzer = PiiAnalyzer()

    proxy_payload = json.dumps(
        {
            "headers": {
                "Origin": ["http://localhost:8082/nexus-backend/mock/v1/echo"],
                "content-length": ["6"],
                "cookie": ["JSESSIONID=CEA39B86F7A90DC01566CF8D42BF80DB"],
                "host": ["localhost:8082"],
                "content-type": ["application/json"],
                "user-agent": ["AutoSwagger2/1.3.0"],
            }
        },
        separators=(",", ":"),
    )
    detected_proxy, data_proxy = analyzer.analyze_content(proxy_payload)
    assert detected_proxy is False
    assert data_proxy == {}

    iso_payload = json.dumps(
        {"data1": "test", "data2": "info2", "data3": 10.05, "data4": "2026-11-15T13:05:13.735Z"},
        separators=(",", ":"),
    )
    detected_iso, data_iso = analyzer.analyze_content(iso_payload)
    assert detected_iso is False
    assert data_iso == {}

    user_me_payload = json.dumps(
        {"username": "test", "email": "test", "role": "test"},
        separators=(",", ":"),
    )
    detected_user, data_user = analyzer.analyze_content(user_me_payload)
    assert detected_user is False
    assert "PASSPORT_NUMBER" not in data_user


def test_presidio_identity_and_financial_data_accuracy():
    analyzer = PiiAnalyzer()

    identity_payload = json.dumps(
        [
            {"data1": "user_name", "data2": "Jane Doe", "data3": 0.0},
            {"data1": "passport_number", "data2": "AB123456", "data3": 0.0},
            {"data1": "ssn", "data2": "123-45-6789", "data3": 0.0},
        ],
        separators=(",", ":"),
    )
    detected_id, data_id = analyzer.analyze_content(identity_payload)
    assert detected_id is True
    assert set(data_id.keys()) == {"US_SSN", "PERSON", "PASSPORT_NUMBER"}
    assert "Jane Doe" in data_id["PERSON"]["values"]
    assert "AB123456" in data_id["PASSPORT_NUMBER"]["values"]
    assert "123-45-6789" in data_id["US_SSN"]["values"]

    financial_payload = json.dumps(
        {
            "transaction_id": "TXN-12345",
            "beneficiary_iban": "00:1A:2B:3C:4D:5E",
            "card_number": "4971 1234 5678 9010",
            "payment_method": "credit_card",
        },
        separators=(",", ":"),
    )
    detected_fin, data_fin = analyzer.analyze_content(financial_payload)
    assert detected_fin is True
    assert set(data_fin.keys()) == {"CREDIT_CARD_NUMBER", "MAC_ADDRESS"}
    assert "4971 1234 5678 9010" in data_fin["CREDIT_CARD_NUMBER"]["values"]
    assert "00:1A:2B:3C:4D:5E" in data_fin["MAC_ADDRESS"]["values"]


def test_presidio_data_joe_and_vehicle_plates():
    analyzer = PiiAnalyzer()
    validator = ResultValidator()

    data_joe_payload = json.dumps(
        {
            "dataJoe": {
                "address": "123 Fake Street",
                "phone": "+1-555-123-4567",
                "name": "John Doe",
                "userid": 123,
                "email": "john.doe@example.com",
            }
        },
        separators=(",", ":"),
    )
    detected_joe, data_joe = analyzer.analyze_content(data_joe_payload)
    assert detected_joe is True
    assert "ADDRESS" in data_joe
    assert "PHONE_NUMBER" in data_joe
    assert "EMAIL_ADDRESS" in data_joe
    assert "PERSON" in data_joe
    assert "John Doe" in data_joe["PERSON"]["values"]
    assert "Fake Street" not in data_joe["PERSON"]["values"]

    norm_joe, _ = validator.validate_finding(data_joe)
    assert "EMAIL_ADDRESS" in norm_joe
    assert "john.doe@example.com" in norm_joe["EMAIL_ADDRESS"]

    vehicle_payload = json.dumps(
        {
            "vehicle_us": "ABC 1234",
            "license_plate_fr": "AB-123-CD",
            "vehicule_fr": "Peugeot 208",
            "license_plate_us": "ABC 1234",
        },
        separators=(",", ":"),
    )
    detected_veh, data_veh = analyzer.analyze_content(vehicle_payload)
    assert detected_veh is True
    assert set(data_veh.keys()) == {"FR_LICENSE_PLATE", "US_LICENSE_PLATE"}
    assert data_veh["FR_LICENSE_PLATE"]["values"] == {"AB-123-CD"}
    assert data_veh["US_LICENSE_PLATE"]["values"] == {"ABC 1234"}
