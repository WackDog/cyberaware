import pytest

from app import create_app


@pytest.fixture()
def client():
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret"})
    return app.test_client()


def start_training(client):
    return client.post("/start", follow_redirects=True)


def test_home_page_loads(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Learn to spot the warning signs" in response.data


def test_start_training_loads_first_scenario(client):
    response = start_training(client)
    assert response.status_code == 200
    assert b"Scenario 1 of 3" in response.data
    assert b"mailbox will be disabled" in response.data


def test_missing_classification_returns_validation_error(client):
    start_training(client)
    response = client.post(
        "/submit",
        data={"indicators": ["urgent"]},
        follow_redirects=True,
    )
    assert response.status_code == 400
    assert b"Choose whether the message is phishing or legitimate" in response.data


def test_correct_answer_awards_points_and_shows_feedback(client):
    start_training(client)
    response = client.post(
        "/submit",
        data={
            "classification": "phishing",
            "indicators": ["urgent", "credential", "domain"],
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Correct classification" in response.data
    assert b"+5 / 5 points" in response.data


def test_complete_training_reaches_results(client):
    start_training(client)

    answers = [
        ("phishing", ["urgent", "credential", "domain"]),
        ("legitimate", []),
        ("phishing", ["payment", "ip-host", "pressure"]),
    ]

    for classification, indicators in answers:
        client.post(
            "/submit",
            data={"classification": classification, "indicators": indicators},
        )
        response = client.post("/next", follow_redirects=True)

    assert response.status_code == 200
    assert b"Training complete" in response.data
    assert b"100%" in response.data
    assert b"3" in response.data


def test_restart_resets_progress(client):
    start_training(client)
    client.post(
        "/submit",
        data={
            "classification": "phishing",
            "indicators": ["urgent", "credential", "domain"],
        },
    )
    client.post("/next")

    response = client.post("/restart", follow_redirects=True)
    assert b"Scenario 1 of 3" in response.data
    assert b"Score 0" in response.data


def test_url_checker_page_loads(client):
    response = client.get("/url-checker")
    assert response.status_code == 200
    assert b"Check an unfamiliar URL" in response.data


def test_url_checker_rejects_empty_input(client):
    response = client.post("/url-checker", data={"url": ""})
    assert response.status_code == 200
    assert b"Enter a URL to analyse" in response.data


def test_url_checker_displays_detected_warnings(client):
    response = client.post(
        "/url-checker",
        data={"url": "http://203.0.113.42/login"},
    )
    assert response.status_code == 200
    assert b"IP address used as the hostname" in response.data
    assert b"HTTP rather than HTTPS" in response.data
    assert b"account or security-related wording" in response.data
    assert b"High caution level" in response.data

def test_submitting_same_scenario_twice_does_not_award_points_twice(client):
    start_training(client)

    answer = {
        "classification": "phishing",
        "indicators": ["urgent", "credential", "domain"],
    }

    client.post("/submit", data=answer)
    client.post("/submit", data=answer)

    with client.session_transaction() as session:
        assert session["score"] == 5
        assert session["answered"] == 1