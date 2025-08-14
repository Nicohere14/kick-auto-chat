# kick-auto-chat (legal/consent-based)
Zbudowano: 2025-08-14T20:49:04.571247Z

Automatyczny bot do Kick.com: startuje przy **LIVE**, wysyła wiadomość co N minut (z jitterem), zatrzymuje się po OFF. Używaj tylko na swoim kanale lub za zgodą.

## Start
1. Utwórz app na https://dev.kick.com i wstaw Webhook URL: `https://twoj-host/webhook`.
2. Skopiuj `.env.example` → `.env`, uzupełnij dane.
3. `npm install` i `npm start`.
4. Wejdź na `https://twoj-host/auth/start` po pierwszy login.
