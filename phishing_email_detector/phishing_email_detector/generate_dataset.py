"""
generate_dataset.py
--------------------
Builds a labeled dataset of phishing vs. legitimate emails and saves it
to data/emails.csv. Combines realistic phishing/legitimate templates
with randomized variation (sender domains, links, names, amounts) so
the model sees varied but plausible examples.

Run this once before train_model.py:
    python generate_dataset.py
"""

import random
import csv
import os

random.seed(42)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_PATH = os.path.join(APP_DIR, "data", "emails.csv")

FIRST_NAMES = ["John", "Priya", "Alex", "Maria", "Ahmed", "Chen", "Sara", "David", "Anita", "Robert"]

LEGIT_DOMAINS = [
    "company.com", "university.edu", "workplace.org", "bank-official.com",
    "amazon.com", "google.com", "microsoft.com", "github.com", "linkedin.com",
]

PHISHY_DOMAINS = [
    "secure-login-verify.com", "account-update-now.net", "paypa1-security.com",
    "bank0famerica-alert.com", "appleid-confirm.info", "amaz0n-support.xyz",
    "verify-microsft.com", "urgent-tax-refund.co", "netfliix-billing.com",
    "linkedln-security.net",
]

URGENT_PHRASES = [
    "Your account has been suspended", "Immediate action required",
    "Verify your account within 24 hours", "Unusual activity detected",
    "Your payment could not be processed", "You have won a prize",
    "Your password will expire today", "Confirm your identity now",
    "Your account will be locked", "Claim your refund before it expires",
]

LEGIT_SUBJECTS = [
    "Meeting rescheduled to next week", "Your invoice for this month",
    "Weekly newsletter update", "Project deadline reminder",
    "Your order has shipped", "Welcome to the team",
    "Notes from today's standup", "Your subscription receipt",
    "Reminder: submit your timesheet", "Congratulations on your promotion",
]

LEGIT_BODY_TEMPLATES = [
    "Hi {name},\n\nJust a reminder that our meeting has been moved to {day} at {time}. "
    "Let me know if that works for you.\n\nBest,\nTeam",
    "Hi {name},\n\nAttached is your invoice for this month's services. "
    "Please review it at your convenience and reach out with any questions.\n\nThanks,\nBilling Team",
    "Hello {name},\n\nHere is this week's newsletter with updates from the team. "
    "No action is needed on your part.\n\nRegards,\nNewsletter Team",
    "Hi {name},\n\nYour order #{order} has shipped and should arrive within 3-5 business days. "
    "You can track it from your account dashboard.\n\nThanks for shopping with us!",
    "Hi {name},\n\nWelcome aboard! Your onboarding materials are in the shared drive. "
    "Reach out if you have any questions during your first week.\n\nBest,\nHR",
    "Hi {name},\n\nJust a friendly reminder to submit your timesheet by Friday. "
    "Let your manager know if you need an extension.\n\nThanks,\nOps",
]

PHISHING_BODY_TEMPLATES = [
    "Dear Customer,\n\n{urgent}. Click here immediately to verify your account: "
    "http://{domain}/verify?user={rand}\n\nFailure to act within 24 hours will result in permanent suspension.\n\nSecurity Team",
    "URGENT: {urgent}.\n\nWe detected a login from an unrecognized device. "
    "Confirm it was you by logging in here: http://{domain}/login-alert?id={rand}\n\nIf you do not respond, your account will be locked.",
    "Dear {name},\n\nCongratulations! You have been selected to receive a refund of ${amount}. "
    "Claim it now at http://{domain}/claim?ref={rand} before this offer expires.\n\nAct now!",
    "ATTENTION: {urgent}.\n\nYour payment method on file has expired. Update it immediately at "
    "http://{domain}/update-billing?token={rand} to avoid service interruption.",
    "Dear Valued Customer,\n\n{urgent}. For your security, we have temporarily limited your account. "
    "Restore full access here: http://{domain}/restore?case={rand}\n\nThis is your final notice.",
    "Hello,\n\nYour tax refund of ${amount} is pending. {urgent}. "
    "Submit your details now at http://{domain}/refund-form?id={rand} to receive your payment.",
]


def gen_legit_email():
    name = random.choice(FIRST_NAMES)
    subject = random.choice(LEGIT_SUBJECTS)
    body_template = random.choice(LEGIT_BODY_TEMPLATES)
    body = body_template.format(
        name=name,
        day=random.choice(["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]),
        time=random.choice(["9:00 AM", "11:30 AM", "2:00 PM", "4:15 PM"]),
        order=random.randint(10000, 99999),
    )
    sender = f"{name.lower()}@{random.choice(LEGIT_DOMAINS)}"
    full_text = f"Subject: {subject}\nFrom: {sender}\n\n{body}"
    return full_text, 0  # 0 = legitimate/safe


def gen_phishing_email():
    name = random.choice(FIRST_NAMES)
    urgent = random.choice(URGENT_PHRASES)
    domain = random.choice(PHISHY_DOMAINS)
    body_template = random.choice(PHISHING_BODY_TEMPLATES)
    body = body_template.format(
        urgent=urgent,
        domain=domain,
        rand=random.randint(100000, 999999),
        name=name,
        amount=random.choice([49.99, 120.00, 250.50, 899.00, 1500.00]),
    )
    sender = f"security-alert@{domain}"
    subject = urgent
    full_text = f"Subject: {subject}\nFrom: {sender}\n\n{body}"
    return full_text, 1  # 1 = phishing


def build_dataset(n_per_class: int = 400):
    rows = []
    for _ in range(n_per_class):
        rows.append(gen_legit_email())
    for _ in range(n_per_class):
        rows.append(gen_phishing_email())
    random.shuffle(rows)
    return rows


def main():
    rows = build_dataset(n_per_class=400)
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label"])  # label: 1 = phishing, 0 = safe
        writer.writerows(rows)
    print(f"Wrote {len(rows)} emails to {OUT_PATH}")


if __name__ == "__main__":
    main()
