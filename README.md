# Project name Encrypto Messaging Application-Developement

This web application is a security focused encrypted chat system built with Flask, AES-GCM encryption, Argon2 hashing, CSRF protection, brute-force lockout,
and automated Selenium penetration tests for both branches secure and insecure.

To set up this project you may need to create a .venv

In your terminal Enter  python -m venv .venv

On Mac
Activate the .venv by entering  source .venv/bin/activate  

On Windows  
Activate the by entering .venv\Scripts\activate

Once your virtual enviroment .venv is activated in your terminal enter pip install -r requirements.txt
This will allow you to run the application using Python app.py The application wil host on <http://127.0.0.1:5000>

To run the test you may need to install  
brew install --cask chromedriver.

For thes test to work the application must be running. Ensure the application is running when your run python tests/test.apy on both branches
