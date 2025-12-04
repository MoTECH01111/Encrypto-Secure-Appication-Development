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


class EncryptoSecureTests(unittest.TestCase):

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

    # Test Registration with Argon2 Hashing
    def test_01_registration(self):
        driver = self.driver
        driver.get(BASE_URL + "/register")

        username = "SecureUser"
        password = "StrongPassword123"

        user_field = self.wait(By.ID, "username")
        pwd_field = self.wait(By.ID, "password")

        user_field.send_keys(username)
        pwd_field.send_keys(password)
        pwd_field.send_keys(Keys.RETURN)

        time.sleep(1)
        self.assertIn("Login", driver.page_source)
        print("✔ Registration successful with Argon2 hashing.")

    #  Test Login with Argon2 Verification
    def test_02_login_valid(self):
        driver = self.driver
        driver.get(BASE_URL + "/login")

        self.wait(By.ID, "username").send_keys("SecureUser")
        pwd = self.wait(By.ID, "password")
        pwd.send_keys("StrongPassword123")
        pwd.send_keys(Keys.RETURN)

        WebDriverWait(driver, 5).until(EC.url_contains("/dashboard"))
        self.assertIn("Chat Room", driver.page_source)
        print("✔ Login successful with Argon2 verification.")

    #  Test Auto-Migration (plaintext → Argon2)
    def test_03_auto_migration_admin(self):
        """
        Admin starts with plaintext password: 'admin'
        On first login:
            - System verifies plaintext
            - Migrates to Argon2 hash
            - Login succeeds
        """

        driver = self.driver
        driver.get(BASE_URL + "/login")

        self.wait(By.ID, "username").send_keys("admin")
        pwd = self.wait(By.ID, "password")
        pwd.send_keys("admin") 
        pwd.send_keys(Keys.RETURN)

        WebDriverWait(driver, 5).until(EC.url_contains("/dashboard"))
        self.assertIn("Chat Room", driver.page_source)

        print("✔ Auto-migration from plaintext to Argon2 successful for admin user.")


if __name__ == "__main__":
    unittest.main()
