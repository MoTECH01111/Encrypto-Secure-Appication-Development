import time
import unittest
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

# Base URL
BASE_URL = "http://127.0.0.1:5000"

class EncryptoSeleniumTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        options = webdriver.ChromeOptions()
        options.add_argument("--disable-popup-blocking")     # Prevent popups blocks for test
        options.add_argument("--disable-notifications")      # Disable notifications

        # Automatically install and launch ChromeDriver
        cls.driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()),
            options=options
        )
        cls.driver.maximize_window()  # Better visibility while test ongoing

    @classmethod
    def tearDownClass(cls):
        # Close the browser after all tests complete
        cls.driver.quit()


    # Wait for an element to appear on the page
    def wait(self, by, value, timeout=10):
        return WebDriverWait(self.driver, timeout).until(
            EC.presence_of_element_located((by, value))
        )

    # Check if a JavaScript alert is open
    def try_close_alert(self):
        try:
            alert = WebDriverWait(self.driver, 1).until(EC.alert_is_present())
            text = alert.text
            alert.accept()  # Close alert
            return text
        except:
            return None


    # Registration Test
    def test_01_registration(self):
        driver = self.driver
        driver.get(BASE_URL + "/register")

        # Insert registration form
        username = self.wait(By.ID, "username")
        password = self.wait(By.ID, "password")

        username.send_keys("User")
        password.send_keys("password123")
        password.send_keys(Keys.RETURN) 

        time.sleep(1)

        # Successful registration should redirect to Login 
        self.assertIn("Login", driver.page_source)
        print(" Registration successful.")

    # Valid Login Test
    def test_02_login_valid(self):
        driver = self.driver
        driver.get(BASE_URL + "/login")
        self.try_close_alert()

        # Enter valid credentials
        self.wait(By.ID, "username").send_keys("User")
        pwd = self.wait(By.ID, "password")
        pwd.send_keys("password123")
        pwd.send_keys(Keys.RETURN)

        self.try_close_alert()

        # Should redirect to dashboard
        WebDriverWait(driver, 5).until(EC.url_contains("/dashboard"))
        self.assertIn("Chat Room", driver.page_source)
        print(" Login successful.")


    # SQL Injection Login Test
    def test_03_login_sql_injection(self):
        driver = self.driver
        driver.get(BASE_URL + "/login")
        self.try_close_alert()

        # SQL injection payload checks if bypasses weak login 
        self.wait(By.ID, "username").send_keys("' OR '1'='1")
        pwd = self.wait(By.ID, "password")
        pwd.send_keys("anything")
        pwd.send_keys(Keys.RETURN)

        self.try_close_alert()
        time.sleep(1)

        # Checks If SQLi bypass works, it should login 
        self.assertNotIn("Incorrect username or password", driver.page_source)
        print(" SQL injection bypassed login.")


    #Reflected XSS Test
    def test_04_reflected_xss(self):
        driver = self.driver
        driver.get(BASE_URL + "/register")
        self.try_close_alert()

        # JavaScript payload for reflected XSS
        payload = "<script>alert('ReflectedXSS')</script>"

        # Enter payload into username field
        self.wait(By.ID, "username").send_keys(payload)
        pwd = self.wait(By.ID, "password")
        pwd.send_keys("abc")
        pwd.send_keys(Keys.RETURN)

        # the script executes and an alert appears
        alert = WebDriverWait(driver, 5).until(EC.alert_is_present())
        self.assertIn("ReflectedXSS", alert.text)
        alert.accept()

        print("Reflected XSS works.")

    #Login as Valid User for XSS Tests
    def login_as_user(self):
        driver = self.driver
        driver.get(BASE_URL + "/login")
        self.try_close_alert()

        username = self.wait(By.ID, "username")
        password = self.wait(By.ID, "password")

        username.clear()
        password.clear()
        username.send_keys("User")
        password.send_keys("password123")
        password.send_keys(Keys.RETURN)

        self.try_close_alert()

        # Make sure dashboard loads
        WebDriverWait(driver, 5).until(EC.url_contains("/dashboard"))

    # Stored XSS Test
    def test_05_stored_xss(self):
        """
        Confirms the chat dashboard loads — this test does not yet inject XSS.
        """
        driver = self.driver
        driver.get(f"{BASE_URL}/dashboard")

        # The chat UI should load
        self.assertIn("Chat Room", driver.page_source)
        print(" Chat Room loads without error.")


    # DOM-based XSS Test
    def test_06_dom_xss(self):
        driver = self.driver
        self.login_as_user()

        # Payload that triggers JS through an HTML attribute
        payload = '<img src=x onerror="alert(\'DOMXSS\')">'

        receiver = self.wait(By.ID, "receiver")
        content = self.wait(By.ID, "content")

        # Form inputs
        receiver.clear()
        receiver.send_keys("User")
        content.clear()
        content.send_keys(payload)

        # Send message
        send_btn = self.wait(By.CSS_SELECTOR, "form button[type='submit']")
        send_btn.click()

        time.sleep(1)

        # Execute the payload and show an alert
        alert = WebDriverWait(driver, 7).until(EC.alert_is_present())
        self.assertIn("DOMXSS", alert.text)
        alert.accept()

        print("DOM XSS works.")

if __name__ == "__main__":
    unittest.main()
