# VaultIQ 🔐

![Tests](https://github.com/Rohit270727/VaultIQ/actions/workflows/tests.yml/badge.svg)

A secure password manager built with Flask and React Native, featuring AES-256 encryption, TOTP-based 2FA, HaveIBeenPwned breach checking, and biometric unlock.

## Features
- AES-256 encrypted password vault
- TOTP two-factor authentication
- Password strength analysis with entropy scoring
- Breach detection via HaveIBeenPwned API
- Vault health score dashboard
- Dark/light theme toggle
- Rate-limited login and session auto-lock
- Full audit logging

## Tech Stack
- **Backend:** Flask, SQLite
- **Security:** AES-256, PBKDF2, PyOTP
- **Frontend:** HTML/CSS/JS (server-rendered), React Native (Android APK)
- **Testing:** pytest
- **CI:** GitHub Actions

## Running locally