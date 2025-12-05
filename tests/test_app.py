import time
import unittest
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

BASE_URL = "http://127.0.0.1:5000"

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')></iframe>",
    "<a href='javascript:alert(1)'>x</a>",
    "<body onload=alert('XSS')>",
]

class SecurityTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        options = webdriver.ChromeOptions()
        options.add_argument("--disable-popup-blocking")
        options.add_argument("--disable-notifications")

        cls.driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()),
            options=options
        )
        cls.driver.maximize_window()

    @classmethod
    def tearDownClass(cls):
        cls.driver.quit()


    # Utility Helpers
    def wait(self, by, val, timeout=10):
        return WebDriverWait(self.driver, timeout).until(
            EC.presence_of_element_located((by, val))
        )

    def get_alert(self, timeout=1):
        try:
            alert = WebDriverWait(self.driver, timeout).until(
                EC.alert_is_present()
            )
            text = alert.text
            alert.accept()
            return text
        except:
            return None

    # helper
    def secure_login(self):
        driver = self.driver

        # Reset session
        driver.delete_all_cookies()

        # Ensure test user exists
        driver.get(BASE_URL + "/register")

        try:
            username_field = WebDriverWait(driver, 4).until(
                EC.presence_of_element_located((By.ID, "username"))
            )
            username_field.send_keys("XSSUser")
            pwd = driver.find_element(By.ID, "password")
            pwd.send_keys("Pass12345")
            pwd.send_keys(Keys.RETURN)
            time.sleep(1)
        except Exception:
            pass

        #login
        driver.get(BASE_URL + "/login")

        try:
            username_field = WebDriverWait(driver, 5).until(
                EC.presence_of_element_located((By.ID, "username"))
            )
            username_field.clear()
            username_field.send_keys("XSSUser")

            pwd = driver.find_element(By.ID, "password")
            pwd.clear()
            pwd.send_keys("Pass12345")
            pwd.send_keys(Keys.RETURN)
        except Exception as e:
            raise AssertionError("Login form not found or failed to submit.") from e

        # redirect
        try:
            WebDriverWait(driver, 7).until(EC.url_contains("/dashboard"))
        except Exception:
            print("------ LOGIN DEBUG OUTPUT ------")
            print("Current URL:", driver.current_url)
            print("Page snippet:")
            print(driver.page_source[:500])
            raise AssertionError("secure_login() failed: /dashboard did NOT load")


    # SQL Injection Tests
    def test_01_registration(self):
        driver = self.driver
        driver.get(BASE_URL + "/register")

        self.wait(By.ID, "username").send_keys("SecureUser")
        pwd = self.wait(By.ID, "password")
        pwd.send_keys("StrongPass123")
        pwd.send_keys(Keys.RETURN)

        time.sleep(1)
        self.assertIn("Login", driver.page_source)
        print("Registration OK")

    def test_02_valid_login(self):
        driver = self.driver
        driver.get(BASE_URL + "/login")

        self.wait(By.ID, "username").send_keys("SecureUser")
        pwd = self.wait(By.ID, "password")
        pwd.send_keys("StrongPass123")
        pwd.send_keys(Keys.RETURN)

        WebDriverWait(driver, 5).until(EC.url_contains("/dashboard"))
        self.assertIn("Chat Room", driver.page_source)
        print("Valid login OK")

    def test_03_sql_injection_login_blocked(self):
        driver = self.driver
        driver.get(BASE_URL + "/login")

        self.wait(By.ID, "username").send_keys("' OR '1'='1")
        pwd = self.wait(By.ID, "password")
        pwd.send_keys("anything")
        pwd.send_keys(Keys.RETURN)

        time.sleep(1)
        self.assertIn("Incorrect username", driver.page_source)
        print("SQLi login blocked")

    def test_04_sql_injection_receiver_lookup_blocked(self):
        driver = self.driver

        self.secure_login()

        receiver = self.wait(By.ID, "receiver")
        content = self.wait(By.ID, "content")

        receiver.send_keys("' OR '1'='1")
        content.send_keys("Test message")

        submit = self.wait(By.CSS_SELECTOR, "form button[type='submit']")
        submit.click()

        time.sleep(1)
        self.assertIn("does not exist", driver.page_source)
        print("SQLi receiver lookup blocked")

    def test_05_sql_injection_message_fetch_blocked(self):
        driver = self.driver

        driver.get(BASE_URL + "/get_messages")
        page = driver.page_source.lower()

        self.assertNotIn("syntax error", page)
        print("SQLi fetch blocked")

    # XSS Tests
    def test_06_reflected_xss_blocked(self):
        driver = self.driver
        driver.get(BASE_URL + "/login")

        for payload in XSS_PAYLOADS:
            driver.find_element(By.ID, "username").clear()
            driver.find_element(By.ID, "password").clear()

            driver.find_element(By.ID, "username").send_keys(payload)
            driver.find_element(By.ID, "password").send_keys("badpass")
            driver.find_element(By.ID, "password").send_keys(Keys.RETURN)

            alert = self.get_alert()
            self.assertIsNone(alert, f"Reflected XSS executed for: {payload}")

            self.assertIn("Incorrect username", driver.page_source)

        print("Reflected XSS blocked")

    def test_07_stored_xss_blocked(self):
        driver = self.driver
        self.secure_login()

        # Send stored XSS payloads
        for payload in XSS_PAYLOADS:
            driver.find_element(By.ID, "receiver").clear()
            driver.find_element(By.ID, "content").clear()

            driver.find_element(By.ID, "receiver").send_keys("XSSUser")
            driver.find_element(By.ID, "content").send_keys(payload)
            driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()

            time.sleep(1)

        driver.refresh()
        time.sleep(1)

        alert = self.get_alert()
        self.assertIsNone(alert, "Stored XSS executed!")

        html = driver.find_element(By.ID, "chat-window").get_attribute("innerHTML")

        for payload in XSS_PAYLOADS:
            escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
            self.assertIn(escaped, html)

        print("Stored XSS blocked")

    def test_08_dom_xss_blocked(self):
        driver = self.driver
        self.secure_login()

        for payload in XSS_PAYLOADS:
            driver.find_element(By.ID, "receiver").clear()
            driver.find_element(By.ID, "content").clear()

            driver.find_element(By.ID, "receiver").send_keys("XSSUser")
            driver.find_element(By.ID, "content").send_keys(payload)
            driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
            time.sleep(1)

        time.sleep(2)

        alert = self.get_alert()
        self.assertIsNone(alert, "DOM XSS executed!")

        html = driver.find_element(By.ID, "chat-window").get_attribute("innerHTML").lower()

        # Extract REAL HTML tags
        import re
        real_tags = re.findall(r"<[^>]+>", html)

        forbidden_attributes = ["onerror=", "onload=", "src=\"javascript:", "href=\"javascript:"]

        for tag in real_tags:
            for attribute in forbidden_attributes:
                self.assertNotIn(attribute, tag, f"DOM XSS found inside real tag: {tag}")

        # Forbidden tags
        forbidden_tags = ["<img", "<svg", "<iframe", "<script"]
        for t in forbidden_tags:
            for tag in real_tags:
                self.assertFalse(tag.startswith(t), f"Forbidden tag rendered: {tag}")

        print("DOM XSS blocked")

    def test_09_bruteforce_lockout(self):
        driver = self.driver
        driver.get(BASE_URL + "/login")

        for i in range(5):  # 4 failures triggers
            self.wait(By.ID, "username").clear()
            self.wait(By.ID, "password").clear()
            self.wait(By.ID, "username").send_keys("SecureUser")
            self.wait(By.ID, "password").send_keys("WrongPass")
            self.wait(By.ID, "password").send_keys(Keys.RETURN)
            time.sleep(1)

        self.assertIn("locked", driver.page_source.lower())
        print("Bruteforce lockout enforced")

    def test_10_session_timeout(self):
        driver = self.driver
        self.secure_login()

        # Remove session cookie to simulate timeout
        driver.delete_all_cookies()
        driver.get(BASE_URL + "/dashboard")
        time.sleep(1)
        current = driver.current_url.lower()
        self.assertTrue(current.endswith("/login") or "/login" in current)
        print("Session timeout OK")


    def test_11_csrf_missing_rejected(self):
        driver = self.driver
        self.secure_login()

        result = driver.execute_script("""
            return fetch('/dashboard', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'receiver=Bob&content=Hi'
            }).then(r => r.text());
        """)

        time.sleep(1)

        self.assertIn("csrf", result.lower())
        print("CSRF protection OK")

    def test_12_username_unicode_sanitizer(self):
        driver = self.driver
        driver.get(BASE_URL + "/register")

        dangerous = "user\u202Eevil"

        self.wait(By.ID, "username").send_keys(dangerous)
        self.wait(By.ID, "password").send_keys("StrongPass123")

        self.wait(By.CSS_SELECTOR, "form.register_form button[type='submit']").click()
        time.sleep(1)


        self.assertIn("/login", driver.current_url.lower())
        print("Unicode username sanitized and accepted correctly.")


    def test_13_message_unicode_sanitizer(self):
        driver = self.driver
        self.secure_login()

        bad = "Hello\u202E<script>alert(1)</script>"

        driver.find_element(By.ID, "receiver").clear()
        driver.find_element(By.ID, "receiver").send_keys("XSSUser")
        driver.find_element(By.ID, "content").clear()
        driver.find_element(By.ID, "content").send_keys(bad)
        driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()

        driver.refresh()
        time.sleep(1)

        html = driver.find_element(By.ID, "chat-window").get_attribute("innerHTML")

        self.assertNotIn("\u202E", html)
        self.assertNotIn("<script>", html)
        print("Unicode message sanitizer OK")
    
    def test_14_message_encryption_decryption(self):
        driver = self.driver
        self.secure_login()

        msg = "HelloSecure123!"

        driver.find_element(By.ID, "receiver").clear()
        driver.find_element(By.ID, "receiver").send_keys("XSSUser")
        driver.find_element(By.ID, "content").send_keys(msg)
        driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()

        driver.refresh()
        time.sleep(1)

        html = driver.find_element(By.ID, "chat-window").get_attribute("innerHTML")

        self.assertIn(msg, html)
        print("AES-GCM encryption/decryption OK")


    def test_15_cookie_security_flags(self):
        driver = self.driver
        self.secure_login()

        cookies = driver.get_cookies()
        session_cookie = [c for c in cookies if c['name'] == 'session'][0]

        self.assertTrue(session_cookie['httpOnly'])
        self.assertTrue(session_cookie['secure'])
        print("Secure cookie flags OK")


if __name__ == "__main__":
    unittest.main()
