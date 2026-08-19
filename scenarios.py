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
            "Hello,\n\nYour reserved copy of 'Human Factors in Cybersecurity' is ready for collection. "
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
    {
        "id": "scenario-4",
        "sender": "University IT <it-notices@university.example>",
        "subject": "Your password was changed successfully",
        "body": (
            "Hello,\n\nThis is a confirmation that the password for your university account was changed at 14:32 today. "
            "If you made this change, no action is required. If you did not, contact the IT Service Desk using the "
            "number or support portal listed on the university website.\n\nUniversity IT"
        ),
        "classification": "legitimate",
        "indicator_ids": [],
        "indicators": [
            {
                "id": "password-topic",
                "label": "The message mentions a password",
                "explanation": "Mentioning a password is not automatically suspicious. This message does not ask the user to reveal it or follow an embedded link.",
            },
            {
                "id": "no-action",
                "label": "The message says no action is required if the change was expected",
                "explanation": "This reduces pressure rather than forcing an immediate response.",
            },
            {
                "id": "known-channel",
                "label": "The message advises using a known support channel",
                "explanation": "Directing the user to independently find the official support channel is safer than providing an unfamiliar sign-in link.",
            },
        ],
        "explanation": (
            "This is a legitimate training example. It confirms an account event without asking for credentials, "
            "does not contain an embedded sign-in link, and tells the user to use an independently known support channel if needed."
        ),
    },
    {
        "id": "scenario-5",
        "sender": "Course Documents <sharing@cloud-docs-access.example>",
        "subject": "Document shared with you: Assessment feedback",
        "body": (
            "A lecturer has shared 'Assessment feedback.pdf' with you. Access expires in 2 hours. "
            "Sign in with your university account to view the document:\n\n"
            "https://university-files.cloud-docs-access.example/login"
        ),
        "classification": "phishing",
        "indicator_ids": ["unexpected-share", "lookalike-domain", "expiry-pressure"],
        "indicators": [
            {
                "id": "unexpected-share",
                "label": "The document share is unexpected",
                "explanation": "Unexpected document invitations should be verified using the normal learning platform or a known contact method.",
            },
            {
                "id": "lookalike-domain",
                "label": "The link uses a convincing but unrelated domain",
                "explanation": "The word 'university' appears in the subdomain, but the actual fictional domain is cloud-docs-access.example.",
            },
            {
                "id": "expiry-pressure",
                "label": "The message uses a short expiry time to create pressure",
                "explanation": "A short deadline can discourage the recipient from checking whether the invitation is genuine.",
            },
            {
                "id": "pdf",
                "label": "The filename ends in .pdf",
                "explanation": "A PDF filename is not itself evidence of phishing; context, sender and destination are more important.",
            },
        ],
        "explanation": (
            "This is a phishing scenario. The message combines an unexpected document share, time pressure and a "
            "lookalike destination. A safer action would be to open the normal learning platform directly and check whether feedback is available there."
        ),
    },
    {
        "id": "scenario-6",
        "sender": "Student Finance <finance@university.example>",
        "subject": "Monthly payment statement available",
        "body": (
            "Hello,\n\nYour monthly payment statement is now available in the student portal. "
            "For security, this email does not contain a login link. Open the student portal using your normal bookmark or the university website.\n\n"
            "Student Finance"
        ),
        "classification": "legitimate",
        "indicator_ids": [],
        "indicators": [
            {
                "id": "finance-topic",
                "label": "The message concerns financial information",
                "explanation": "Financial topics deserve care, but the topic alone does not make a message malicious.",
            },
            {
                "id": "no-login-link",
                "label": "The message deliberately avoids including a login link",
                "explanation": "Encouraging the user to navigate independently to a known portal reduces the risk of link-based phishing.",
            },
            {
                "id": "payment-request",
                "label": "The message asks for an immediate payment",
                "explanation": "This message does not request an immediate payment or card details.",
            },
        ],
        "explanation": (
            "This is a legitimate training example. Although it concerns financial information, it does not request "
            "payment details or credentials and deliberately directs the user to a known portal rather than an embedded link."
        ),
    },
]
