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


class EncryptoSeleniumTests(unittest.TestCase):

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


    def wait(self, by, value, timeout=10):
        return WebDriverWait(self.driver, timeout).until(
            EC.presence_of_element_located((by, value))
        )


    def try_close_alert(self):
        try:
            alert = WebDriverWait(self.driver, 1).until(EC.alert_is_present())
            text = alert.text
            alert.accept()
            return text
        except:
            return None

    # Registration
    def test_01_registration(self):
        driver = self.driver
        driver.get(BASE_URL + "/register")

        username = self.wait(By.ID, "username")
        password = self.wait(By.ID, "password")

        username.send_keys("User")
        password.send_keys("password123")
        password.send_keys(Keys.RETURN)

        time.sleep(1)
        self.assertIn("Login", driver.page_source)
        print(" Registration successful.")

    #  Valid Login
    def test_02_login_valid(self):
        driver = self.driver
        driver.get(BASE_URL + "/login")
        self.try_close_alert()

        self.wait(By.ID, "username").send_keys("User")
        pwd = self.wait(By.ID, "password")
        pwd.send_keys("password123")
        pwd.send_keys(Keys.RETURN)

        self.try_close_alert()

        WebDriverWait(driver, 5).until(EC.url_contains("/dashboard"))
        self.assertIn("Chat Room", driver.page_source)
        print(" Login successful.")

    # SQL injection should log in
    def test_03_login_sql_injection(self):
        driver = self.driver
        driver.get(BASE_URL + "/login")
        self.try_close_alert()

        # SQL injection payload
        self.wait(By.ID, "username").send_keys("' OR '1'='1")
        pwd = self.wait(By.ID, "password")
        pwd.send_keys("anything")
        pwd.send_keys(Keys.RETURN)

        self.try_close_alert()
        time.sleep(1)

        self.assertNotIn("Incorrect username or password", driver.page_source)
        print(" SQL injection bypassed login.")


    #  Reflected XSS
    def test_04_reflected_xss(self):
        driver = self.driver
        driver.get(BASE_URL + "/register")
        self.try_close_alert()

        payload = "<script>alert('ReflectedXSS')</script>"

        self.wait(By.ID, "username").send_keys(payload)
        pwd = self.wait(By.ID, "password")
        pwd.send_keys("abc")
        pwd.send_keys(Keys.RETURN)

        alert = WebDriverWait(driver, 5).until(EC.alert_is_present())
        self.assertIn("ReflectedXSS", alert.text)
        alert.accept()

        print("Reflected XSS works.")

    #  Login as User
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
        WebDriverWait(driver, 5).until(EC.url_contains("/dashboard"))

   
    #  Stored XSS
    def test_05_stored_xss(self):
        """Chat page loads properly."""
        driver = self.driver
        driver.get(f"{BASE_URL}/dashboard")

        #page loads successfully,
        self.assertIn("Chat Room", driver.page_source)



    #  DOM XSS
    def test_06_dom_xss(self):
        driver = self.driver
        self.login_as_user()

        payload = '<img src=x onerror="alert(\'DOMXSS\')">'

        receiver = self.wait(By.ID, "receiver")
        content = self.wait(By.ID, "content")
        receiver.clear()
        receiver.send_keys("User")
        content.clear()
        content.send_keys(payload)

        send_btn = self.wait(By.CSS_SELECTOR, "form button[type='submit']")
        send_btn.click()

        time.sleep(1)

        alert = WebDriverWait(driver, 7).until(EC.alert_is_present())
        self.assertIn("DOMXSS", alert.text)
        alert.accept()

        print("DOM XSS works.")



if __name__ == "__main__":
    unittest.main()
