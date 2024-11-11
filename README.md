# KK-Ticketing-2024

This is a ticketing system for the 2024 Kannada Rajyotsava event in PES University, Bangalore. The project uses Flask as the backend and HTML, CSS, and JavaScript for the frontend.
PostgreSQL is used as the database.

The project is divided into two parts:
1. Ticketing System - Where the trusted members are able to issue tickets to the participants.
2. Scanning System - Where the tickets are scanned to verify the participants during the event.

## Installation

1. Clone the repository
```bash
git clone https://github.com/Kannada-Koota-PES/KK-Ticketing-2024.git
```
2. Create and activate a virtual environment
```bash
cd KK-Ticketing-2024
python3 -m venv venv
source venv/bin/activate
```
3. Install the dependencies
```bash
pip install -r app/requirements.txt
```
4. Create a `.env` file in the root directory and add the following environment variables:
```bash
DEBUG = False
SECRET_KEY = ''
DATABASE_URL = ''
```
5. Create and set up the database using the commands in `db_commands.md`
6. Run the application
```bash
cd app
flask run
```

Made with ❤️ by [IT Domain Kannada Koota, PES University](https://github.com/Kannada-Koota-PES)

ಕನ್ನಡ ಕೂಟ 💛❤️