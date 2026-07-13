import math
import re
import hashlib
import requests

def load_common_passwords(filepath="common_passwords.txt"):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return set(line.strip().lower() for line in f)

COMMON_PASSWORDS = load_common_passwords()

def calculate_entropy(password):
    pool = 0
    if re.search(r'[a-z]', password): pool += 26
    if re.search(r'[A-Z]', password): pool += 26
    if re.search(r'[0-9]', password): pool += 10
    if re.search(r'[^a-zA-Z0-9]', password): pool += 32
    if pool == 0: return 0
    return len(password) * math.log2(pool)

def check_strength(password):
    if password.lower() in COMMON_PASSWORDS:
        return "Weak", 0, ["This password appears in known breach lists."]

    entropy = calculate_entropy(password)
    suggestions = []

    if len(password) < 8:
        suggestions.append("Use at least 8 characters.")
    if not re.search(r'[A-Z]', password):
        suggestions.append("Add an uppercase letter.")
    if not re.search(r'[0-9]', password):
        suggestions.append("Add a number.")
    if not re.search(r'[^a-zA-Z0-9]', password):
        suggestions.append("Add a symbol.")
    if re.search(r'(.)\1{2,}', password):
        suggestions.append("Avoid repeated characters.")

    if entropy < 28:
        strength = "Weak"
    elif entropy < 60:
        strength = "Medium"
    else:
        strength = "Strong"

    return strength, round(entropy, 2), suggestions

if __name__ == "__main__":
    while True:
        pw = input("Enter password to test (or 'exit'): ")
        if pw == "exit": break
        strength, entropy, tips = check_strength(pw)
        print(f"Strength: {strength} | Entropy: {entropy} bits")
        if tips: print("Suggestions:", tips)

def check_breach(password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if response.status_code != 200:
            return None  # API issue, skip breach check silently

        hashes = (line.split(":") for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)  # number of times this password was seen in breaches
        return 0  # not found in breaches
    except requests.RequestException:
        return None  # network issue, skip breach check silently  

from datetime import datetime, timezone

def analyze_vault_health(decrypted_entries):
    """decrypted_entries: list of (id, site, username, password, created_at)"""
    total = len(decrypted_entries)
    if total == 0:
        return {"score": 100, "weak": 0, "reused": 0, "old": 0, "total": 0}

    pw_counts = {}
    weak_count = 0
    old_count = 0

    for _id, site, username, pw, created_at in decrypted_entries:
        strength, entropy, _ = check_strength(pw)
        if strength == "Weak":
            weak_count += 1
        pw_counts[pw] = pw_counts.get(pw, 0) + 1

        try:
            created = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
            age_days = (datetime.now() - created).days
            if age_days > 90:
                old_count += 1
        except (ValueError, TypeError):
            pass  # entries created before this feature existed

    reused_count = sum(c for c in pw_counts.values() if c > 1)

    # Weighted score: weak passwords hurt most, then reuse, then age
    penalty = (weak_count * 15) + (reused_count * 10) + (old_count * 5)
    score = max(0, 100 - penalty)

    return {
        "score": round(score),
        "weak": weak_count,
        "reused": reused_count,
        "old": old_count,
        "total": total
    }      