import sys
import requests
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton

VRC_API_URL = "https://api.vrchat.cloud/api/1"
API_KEY = ""  # VRChat API key (if needed)

class TwoFAWindow(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.attempts = 0  # Initialize attempts to track how many times the user has tried
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Enter 2FA Code")
        self.setGeometry(150, 150, 300, 150)

        layout = QVBoxLayout()

        self.label = QLabel("Enter your 2FA code (Email/Auth):")
        layout.addWidget(self.label)

        self.twofa = QLineEdit(self)
        self.twofa.setPlaceholderText("2FA Code")
        layout.addWidget(self.twofa)

        self.submit_button = QPushButton("Submit", self)
        self.submit_button.clicked.connect(self.submit_2fa)
        layout.addWidget(self.submit_button)

        self.status_label = QLabel("")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def submit_2fa(self):
        twofa_code = self.twofa.text()

        if twofa_code:
            self.attempts += 1  # Increment the attempt counter

            headers = {
                "User-Agent": "VRChatClient",
                "Content-Type": "application/json"
            }

            auth = requests.auth.HTTPBasicAuth(self.parent.username_text, self.parent.password_text)
            response = self.parent.session.get(f"{VRC_API_URL}/auth/user", headers=headers, auth=auth, params={"twoFactorAuthCode": twofa_code})

            if response.status_code == 200:
                print("2FA successful!")
                self.parent.auth_token = self.parent.session.cookies.get('auth')  # Correct cookie key
                self.parent.open_feature_screen()  # Call the parent method to open the feature screen
                self.close()  # Close 2FA window
            else:
                print(f"2FA failed, attempt {self.attempts}: {response.status_code}")
                self.status_label.setText(f"Invalid 2FA code. Attempt {self.attempts}.")
        else:
            print("Please enter a 2FA code.")
            self.status_label.setText("Please enter a valid 2FA code.")

class VRChatLogin(QWidget):
    def __init__(self):
        super().__init__()
        self.session = requests.Session()
        self.auth_token = None  # Store auth_token here
        self.initUI()

    def initUI(self):
        self.setWindowTitle("VRChat Login")
        self.setGeometry(100, 100, 300, 200)

        layout = QVBoxLayout()

        self.label = QLabel("Enter your VRChat credentials:")
        layout.addWidget(self.label)

        self.username = QLineEdit(self)
        self.username.setPlaceholderText("Username or Email")
        layout.addWidget(self.username)

        self.password = QLineEdit(self)
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password)

        self.login_button = QPushButton("Login", self)
        self.login_button.clicked.connect(self.authenticate)
        layout.addWidget(self.login_button)

        self.status_label = QLabel("")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def authenticate(self):
        self.username_text = self.username.text()
        self.password_text = self.password.text()

        if not self.username_text or not self.password_text:
            self.status_label.setText("Please enter credentials.")
            return

        headers = {
            "User-Agent": "VRChatClient",
            "Content-Type": "application/json"
        }

        auth = requests.auth.HTTPBasicAuth(self.username_text, self.password_text)
        response = self.session.get(f"{VRC_API_URL}/auth/user", headers=headers, auth=auth)

        if response.status_code == 200 or response.status_code == 403:
            self.open_2fa_window()  # Open the 2FA screen regardless of the response
        elif response.status_code == 401:
            self.status_label.setText("Invalid credentials.")
        else:
            self.status_label.setText(f"Error: {response.status_code}")

    def open_2fa_window(self):
        self.twofa_window = TwoFAWindow(self)
        self.twofa_window.show()
        self.close()  # Close the login screen before showing 2FA

    def open_feature_screen(self):
        self.feature_window = FeatureWindow(self)
        self.feature_window.show()
        self.fetch_instance_info()  # Fetch instance information after login

    def fetch_instance_info(self):
        # Ensure that we have the auth_token stored
        if not self.auth_token:
            print("Auth token not found. Please log in first.")
            return


        # Assume we can query an endpoint to get instance information
        instance_info_url = f"{VRC_API_URL}/instance_info"  # Replace with the correct endpoint if needed
        headers = {
            "User-Agent": "VRChatClient",
            "Authorization": f"Bearer {self.auth_token}"  # Use stored auth token
        }

        response = self.session.get(instance_info_url, headers=headers)

        if response.status_code == 200:
            instance_data = response.json()
            # Process and display instance information
            print("Instance information fetched:")
            print(instance_data)
        else:
            print(f"Error fetching instance information: {response.status_code}")
            print("Response Text:", response.text)  # Print the response body for further debugging

class FeatureWindow(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Feature Screen")
        self.setGeometry(200, 200, 400, 200)

        layout = QVBoxLayout()

        self.label = QLabel("You are now logged in! More features to be added...")
        layout.addWidget(self.label)

        self.setLayout(layout)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = VRChatLogin()
    window.show()
    sys.exit(app.exec())
