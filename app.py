import os
from flask import Flask, render_template, request, redirect, url_for, session

from scenarios import SCENARIOS
from url_checker import analyse_url


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("CYBERAWARE_SECRET_KEY", "dev-only-change-me"),
        TESTING=False,
    )

    if test_config:
        app.config.update(test_config)

    def reset_training():
        session["scenario_index"] = 0
        session["score"] = 0
        session["correct_classifications"] = 0
        session["answered"] = 0
        session["max_score"] = 0

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.post("/start")
    def start():
        reset_training()
        return redirect(url_for("training"))

    @app.get("/training")
    def training():
        if "scenario_index" not in session:
            reset_training()

        index = session["scenario_index"]
        if index >= len(SCENARIOS):
            return redirect(url_for("results"))

        scenario = SCENARIOS[index]
        return render_template(
            "training.html",
            scenario=scenario,
            current=index + 1,
            total=len(SCENARIOS),
            score=session.get("score", 0),
        )

    @app.post("/submit")
    def submit_answer():
        if "scenario_index" not in session:
            return redirect(url_for("index"))

        index = session["scenario_index"]
        if index >= len(SCENARIOS):
            return redirect(url_for("results"))

        scenario = SCENARIOS[index]

        previous_feedback = session.get("last_feedback")
        if (
            previous_feedback
            and previous_feedback.get("scenario_id") == scenario["id"]
        ):
            return redirect(url_for("feedback"))

        classification = request.form.get("classification", "").strip().lower()
        selected_indicators = set(request.form.getlist("indicators"))

        if classification not in {"phishing", "legitimate"}:
            return render_template(
                "training.html",
                scenario=scenario,
                current=index + 1,
                total=len(SCENARIOS),
                score=session.get("score", 0),
                error="Choose whether the message is phishing or legitimate before submitting.",
            ), 400

        expected_classification = scenario["classification"]
        classification_correct = classification == expected_classification

        expected_indicators = set(scenario["indicator_ids"])
        correctly_selected = selected_indicators & expected_indicators
        incorrectly_selected = selected_indicators - expected_indicators
        missed_indicators = expected_indicators - selected_indicators

        classification_points = 2 if classification_correct else 0
        indicator_points = len(correctly_selected)
        score_gained = classification_points + indicator_points
        max_for_scenario = 2 + len(expected_indicators)

        session["score"] = session.get("score", 0) + score_gained
        session["max_score"] = session.get("max_score", 0) + max_for_scenario
        session["answered"] = session.get("answered", 0) + 1
        if classification_correct:
            session["correct_classifications"] = session.get("correct_classifications", 0) + 1

        session["last_feedback"] = {
            "scenario_id": scenario["id"],
            "classification_correct": classification_correct,
            "chosen_classification": classification,
            "expected_classification": expected_classification,
            "correctly_selected": sorted(correctly_selected),
            "incorrectly_selected": sorted(incorrectly_selected),
            "missed_indicators": sorted(missed_indicators),
            "score_gained": score_gained,
            "max_for_scenario": max_for_scenario,
        }

        return redirect(url_for("feedback"))

    @app.get("/feedback")
    def feedback():
        feedback_data = session.get("last_feedback")
        if not feedback_data:
            return redirect(url_for("training"))

        scenario = next(
            (item for item in SCENARIOS if item["id"] == feedback_data["scenario_id"]),
            None,
        )
        if scenario is None:
            return redirect(url_for("training"))

        indicator_lookup = {item["id"]: item for item in scenario["indicators"]}
        return render_template(
            "feedback.html",
            scenario=scenario,
            feedback=feedback_data,
            indicator_lookup=indicator_lookup,
            score=session.get("score", 0),
        )

    @app.post("/next")
    def next_scenario():
        if "scenario_index" not in session:
            return redirect(url_for("index"))

        session["scenario_index"] += 1
        session.pop("last_feedback", None)
        if session["scenario_index"] >= len(SCENARIOS):
            return redirect(url_for("results"))
        return redirect(url_for("training"))

    @app.get("/results")
    def results():
        answered = session.get("answered", 0)
        correct = session.get("correct_classifications", 0)
        score = session.get("score", 0)
        max_score = session.get("max_score", 0)

        accuracy = round((correct / answered) * 100) if answered else 0
        score_percent = round((score / max_score) * 100) if max_score else 0

        return render_template(
            "results.html",
            answered=answered,
            correct=correct,
            score=score,
            max_score=max_score,
            accuracy=accuracy,
            score_percent=score_percent,
        )

    @app.post("/restart")
    def restart():
        reset_training()
        return redirect(url_for("training"))

    @app.route("/url-checker", methods=["GET", "POST"])
    def url_checker():
        result = None
        error = None
        entered_url = ""

        if request.method == "POST":
            entered_url = request.form.get("url", "")
            try:
                result = analyse_url(entered_url)
            except ValueError as exc:
                error = str(exc)

        return render_template(
            "url_checker.html",
            result=result,
            error=error,
            entered_url=entered_url,
        )

    return app


if __name__ == "__main__":
    create_app().run(debug=True)
