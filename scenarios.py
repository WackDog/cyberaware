SCENARIOS = [
    {
        "id": "scenario-1",
        "sender": "IT Support <support@northstar-it-help.com>",
        "subject": "URGENT: Your mailbox will be disabled today",
        "body": (
            "We detected a problem with your account. Your mailbox will be disabled today "
            "unless you confirm your password immediately using the link below.\n\n"
            "https://northstar-login-security.example/reset\n\n"
            "IT Support"
        ),
        "classification": "phishing",
        "indicator_ids": ["urgent", "credential", "domain"],
        "indicators": [
            {
                "id": "urgent",
                "label": "The message creates unnecessary urgency",
                "explanation": "Attackers often use urgency to pressure people into acting before checking the request.",
            },
            {
                "id": "credential",
                "label": "The message asks the user to confirm a password",
                "explanation": "Legitimate support teams should not ask users to provide passwords through an emailed link.",
            },
            {
                "id": "domain",
                "label": "The sender/domain does not match the organisation",
                "explanation": "A lookalike or unrelated domain can indicate impersonation.",
            },
            {
                "id": "greeting",
                "label": "The message uses a generic greeting",
                "explanation": "A generic greeting can be suspicious, but it is not strong evidence on its own in this scenario.",
            },
        ],
        "explanation": (
            "This is a phishing scenario. The message combines urgency, a request involving credentials, "
            "and an unrelated support domain. A safer response would be to open the organisation's normal "
            "IT portal directly or contact support through a known channel."
        ),
    },
    {
        "id": "scenario-2",
        "sender": "Library Services <library@university.example>",
        "subject": "Reminder: reserved book ready for collection",
        "body": (
            "Hello Jack,\n\nYour reserved copy of 'Human Factors in Cybersecurity' is ready for collection. "
            "It will be held at the main desk until Friday. No action is required if you no longer need it.\n\n"
            "Library Services"
        ),
        "classification": "legitimate",
        "indicator_ids": [],
        "indicators": [
            {
                "id": "urgent",
                "label": "The message creates unnecessary urgency",
                "explanation": "This message gives a normal collection deadline rather than pressuring the user to act immediately.",
            },
            {
                "id": "credential",
                "label": "The message asks for credentials",
                "explanation": "The message does not ask for a password, payment, or other sensitive information.",
            },
            {
                "id": "domain",
                "label": "The sender/domain looks inconsistent",
                "explanation": "The sender is presented as the expected university library domain for this fictional scenario.",
            },
        ],
        "explanation": (
            "This is a legitimate training example. It does not request credentials or payment, does not direct "
            "the user to an unfamiliar link, and does not use threatening or high-pressure language."
        ),
    },
    {
        "id": "scenario-3",
        "sender": "Parcel Updates <tracking@delivery-status.example>",
        "subject": "Delivery failed - small fee required",
        "body": (
            "Your parcel could not be delivered. Pay the £1.49 redelivery fee within 30 minutes to prevent return "
            "to sender. Use the payment page below:\n\nhttp://203.0.113.42/redelivery"
        ),
        "classification": "phishing",
        "indicator_ids": ["payment", "ip-host", "pressure"],
        "indicators": [
            {
                "id": "payment",
                "label": "Unexpected small payment request",
                "explanation": "Small unexpected fees are commonly used to make fraudulent payment requests seem believable.",
            },
            {
                "id": "ip-host",
                "label": "The link uses an IP address instead of a normal domain",
                "explanation": "An IP-address link can hide the organisation that operates the site and deserves extra scrutiny.",
            },
            {
                "id": "pressure",
                "label": "The message gives an unusually short deadline",
                "explanation": "A 30-minute deadline pressures the recipient to act without verifying the delivery independently.",
            },
            {
                "id": "parcel",
                "label": "The message mentions a parcel",
                "explanation": "Mentioning a parcel is not itself suspicious; the surrounding request and link are the important indicators.",
            },
        ],
        "explanation": (
            "This is a phishing scenario. The unexpected fee, extreme time pressure and IP-address payment link are "
            "strong warning signs. A safer action would be to visit the delivery company's known website manually "
            "using a genuine tracking number."
        ),
    },
]
