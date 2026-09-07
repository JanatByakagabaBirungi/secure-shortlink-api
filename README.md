# SecureLink API 🔗

A production-ready URL shortener API built with **Python, Flask, and MongoDB**. SecureLink allows authenticated users to generate shortened URLs, safely redirect traffic, and track click analytics.

## 🚀 Features

* **JWT Authentication:** Secure route protection using JSON Web Tokens.
* **Persistent Storage:** MongoDB integration for robust data management.
* **Click Analytics:** Automatically tracks and increments usage statistics for every shortened link.
* **Password Security:** Uses Werkzeug to hash and securely store user passwords.
* **Containerized:** fully configured `Dockerfile` and `docker-compose.yml` for instant setup.

## 🛠 Tech Stack

* **Backend Framework:** Python / Flask
* **Database:** MongoDB / PyMongo
* **Authentication:** PyJWT
* **Deployment:** Docker / Docker Compose

## ⚙️ Quick Start (Docker)

The easiest way to run the API and its database is via Docker Compose.

1. **Clone the repository:**
 