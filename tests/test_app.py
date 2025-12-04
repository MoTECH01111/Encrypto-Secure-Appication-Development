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


class SQLInjectionProtectionTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        options = webdriver.ChromeOptions()
        options.add_argument("--disable-popup-blocking")
        cls.driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()),
            options=options
        )
        cls.driver.maximize_window()

    @classmethod
    def tearDownClass(cls):
        cls.driver.quit()

    def wait(self, by, value, timeout=10):
        return WebDriverWait(self.driver, timeout).until(
            EC.presence_of_element_located((by, value))
        )

    # Registration should still work
    def test_01_registration(self):
        driver = self.driver
        driver.get(BASE_URL + "/register")

        self.wait(By.ID, "username").send_keys("SecureUser")
        pwd = self.wait(By.ID, "password")
        pwd.send_keys("StrongPass123")
        pwd.send_keys(Keys.RETURN)

        time.sleep(1)
        self.assertIn("Login", driver.page_source)
        print("✔ Registration still works with parameterized queries.")


    # Login works normally
    def test_02_valid_login(self):
        driver = self.driver
        driver.get(BASE_URL + "/login")

        self.wait(By.ID, "username").send_keys("SecureUser")
        pwd = self.wait(By.ID, "password")
        pwd.send_keys("StrongPass123")
        pwd.send_keys(Keys.RETURN)

        WebDriverWait(driver, 5).until(EC.url_contains("/dashboard"))
        self.assertIn("Chat Room", driver.page_source)
        print("✔ Valid login works.")

    # SQL Injection should NOT bypass login
    def test_03_sql_injection_login_blocked(self):
        driver = self.driver
        driver.get(BASE_URL + "/login")

        self.wait(By.ID, "username").send_keys("' OR '1'='1")
        pwd = self.wait(By.ID, "password")
        pwd.send_keys("anything")
        pwd.send_keys(Keys.RETURN)

        time.sleep(1)

        # Should NOT log in
        self.assertIn("Incorrect username or password", driver.page_source)
        self.assertNotIn("Chat Room", driver.page_source)
        print(" SQL injection no longer bypasses login.")


    # Messaging lookup cannot be injected
    def test_04_sql_injection_receiver_lookup_blocked(self):
        driver = self.driver

        # First log in
        driver.get(BASE_URL + "/login")
        self.wait(By.ID, "username").send_keys("SecureUser")
        pwd = self.wait(By.ID, "password")
        pwd.send_keys("StrongPass123")
        pwd.send_keys(Keys.RETURN)
        WebDriverWait(driver, 5).until(EC.url_contains("/dashboard"))

        # Try SQL injection on receiver field
        receiver = self.wait(By.ID, "receiver")
        content = self.wait(By.ID, "content")

        receiver.send_keys("' OR '1'='1")
        content.send_keys("Test message")

        submit = self.wait(By.CSS_SELECTOR, "form button[type='submit']")
        submit.click()

        time.sleep(1)

        # Should display error instead of sending to everyone
        self.assertIn("does not exist", driver.page_source)
        print(" SQL injection blocked in message lookup")

    #  Message retrieval cannot be injected
    def test_05_sql_injection_message_fetch_blocked(self):
        driver = self.driver

        # Try injecting chat partner
        driver.execute_script("sessionStorage.setItem('chat_with', \"' OR '1'='1\")")
        driver.get(BASE_URL + "/get_messages")

        # Should NOT return all messages or explode
        page = driver.page_source.lower()

        self.assertNotIn("syntax error", page)
        self.assertNotIn("admin:", page)  # No unintended message leakage

        print(" SQL injection blocked in message retrieval.")


if __name__ == "__main__":
    unittest.main()
