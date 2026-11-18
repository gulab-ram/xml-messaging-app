import requests
import sys
import json
from datetime import datetime

class SecureXMLMessagingTester:
    def __init__(self, base_url="https://secsoap-messaging.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.session = requests.Session()
        self.tests_run = 0
        self.tests_passed = 0
        self.alice_token = None
        self.bob_token = None

    def run_test(self, name, method, endpoint, expected_status, data=None, cookies=None):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = self.session.get(url, headers=headers, cookies=cookies)
            elif method == 'POST':
                response = self.session.post(url, json=data, headers=headers, cookies=cookies)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                if response.headers.get('content-type', '').startswith('application/json'):
                    try:
                        return success, response.json()
                    except:
                        return success, {}
                else:
                    return success, response.text
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                print(f"   Response: {response.text[:200]}")
                return False, {}

        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False, {}

    def test_root_endpoint(self):
        """Test root API endpoint"""
        return self.run_test("Root API Endpoint", "GET", "", 200)

    def test_status_endpoints(self):
        """Test status create and list endpoints"""
        # Test create status
        success, response = self.run_test(
            "Create Status Check",
            "POST", 
            "status",
            200,
            data={"client_name": f"test_client_{datetime.now().strftime('%H%M%S')}"}
        )
        
        if not success:
            return False
            
        # Test list status
        success, _ = self.run_test("List Status Checks", "GET", "status", 200)
        return success

    def test_login(self, username, password):
        """Test login and capture cookies"""
        success, response = self.run_test(
            f"Login as {username}",
            "POST",
            "auth/login",
            200,
            data={"username": username, "password": password}
        )
        
        if success:
            # Store cookies for future requests
            if username == "alice":
                self.alice_cookies = self.session.cookies.get_dict()
            elif username == "bob":
                self.bob_cookies = self.session.cookies.get_dict()
        
        return success

    def test_me_endpoint(self, username):
        """Test /auth/me endpoint with authentication"""
        cookies = self.alice_cookies if username == "alice" else self.bob_cookies
        success, response = self.run_test(
            f"Get user info for {username}",
            "GET",
            "auth/me", 
            200,
            cookies=cookies
        )
        return success, response

    def test_unauthorized_access(self):
        """Test unauthorized access to protected endpoints"""
        # Create a fresh session without cookies
        fresh_session = requests.Session()
        url = f"{self.api_url}/messages/inbox"
        headers = {'Content-Type': 'application/json'}
        
        self.tests_run += 1
        print(f"\n🔍 Testing Unauthorized inbox access...")
        print(f"   URL: {url}")
        
        try:
            response = fresh_session.get(url, headers=headers)
            success = response.status_code == 401
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
            else:
                print(f"❌ Failed - Expected 401, got {response.status_code}")
                print(f"   Response: {response.text[:200]}")
            return success
        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False

    def test_send_message(self, sender_username, recipient, body, metadata=None):
        """Test sending a message"""
        cookies = self.alice_cookies if sender_username == "alice" else self.bob_cookies
        
        message_data = {
            "recipient": recipient,
            "body": body,
            "metadata": metadata or ""
        }
        
        success, response = self.run_test(
            f"Send message from {sender_username} to {recipient}",
            "POST",
            "messages/send",
            200,
            data=message_data,
            cookies=cookies
        )
        
        if success and 'xml' in response:
            print(f"   XML generated successfully (length: {len(response['xml'])} chars)")
            return success, response
        
        return success, {}

    def test_inbox(self, username):
        """Test getting inbox messages"""
        cookies = self.alice_cookies if username == "alice" else self.bob_cookies
        
        success, response = self.run_test(
            f"Get inbox for {username}",
            "GET",
            "messages/inbox",
            200,
            cookies=cookies
        )
        
        if success and isinstance(response, list):
            print(f"   Found {len(response)} messages in inbox")
            for msg in response:
                print(f"   - From {msg.get('sender')}: signature_valid={msg.get('signature_valid')}")
        
        return success, response

    def test_sent_messages(self, username):
        """Test getting sent messages"""
        cookies = self.alice_cookies if username == "alice" else self.bob_cookies
        
        success, response = self.run_test(
            f"Get sent messages for {username}",
            "GET",
            "messages/sent",
            200,
            cookies=cookies
        )
        
        if success and isinstance(response, list):
            print(f"   Found {len(response)} sent messages")
        
        return success, response

    def test_decrypt_message(self, username, message_id):
        """Test decrypting a message"""
        cookies = self.alice_cookies if username == "alice" else self.bob_cookies
        
        success, response = self.run_test(
            f"Decrypt message {message_id} for {username}",
            "POST",
            f"messages/{message_id}/decrypt",
            200,
            cookies=cookies
        )
        
        if success and 'plaintext' in response:
            print(f"   Decrypted text: {response['plaintext'][:50]}...")
        
        return success, response

    def test_xsd_schema(self):
        """Test XSD schema download"""
        success, response = self.run_test(
            "Download XSD Schema",
            "GET",
            "messages/schema",
            200
        )
        
        if success and isinstance(response, str) and 'xs:schema' in response:
            print("   XSD schema contains valid XML schema definition")
        
        return success

    def test_logout(self):
        """Test logout endpoint"""
        success, _ = self.run_test(
            "Logout",
            "POST",
            "auth/logout",
            200,
            cookies=self.alice_cookies
        )
        return success

def main():
    print("🚀 Starting Secure XML Messaging System Backend Tests")
    print("=" * 60)
    
    tester = SecureXMLMessagingTester()
    
    # Initialize cookie storage
    tester.alice_cookies = {}
    tester.bob_cookies = {}
    
    # Test 1: Root endpoint
    if not tester.test_root_endpoint():
        print("❌ Root endpoint failed, stopping tests")
        return 1

    # Test 2: Status endpoints
    if not tester.test_status_endpoints():
        print("❌ Status endpoints failed")
        return 1

    # Test 3: Login as Alice
    if not tester.test_login("alice", "alice123"):
        print("❌ Alice login failed, stopping tests")
        return 1

    # Test 4: Login as Bob
    if not tester.test_login("bob", "bob123"):
        print("❌ Bob login failed, stopping tests")
        return 1

    # Test 5: Test /auth/me for Alice
    success, alice_info = tester.test_me_endpoint("alice")
    if not success:
        print("❌ Alice /auth/me failed")
        return 1

    # Test 6: Test unauthorized access
    if not tester.test_unauthorized_access():
        print("❌ Unauthorized access test failed")
        return 1

    # Test 7: Alice sends message to Bob
    success, sent_message = tester.test_send_message("alice", "bob", "Hello Bob! This is a test message from Alice.", "test=true")
    if not success:
        print("❌ Message sending failed")
        return 1

    # Test 8: Bob checks inbox
    success, bob_inbox = tester.test_inbox("bob")
    if not success:
        print("❌ Bob inbox check failed")
        return 1

    # Test 9: Alice checks sent messages
    success, alice_sent = tester.test_sent_messages("alice")
    if not success:
        print("❌ Alice sent messages check failed")
        return 1

    # Test 10: Bob decrypts the message
    if bob_inbox and len(bob_inbox) > 0:
        message_id = bob_inbox[0]['id']
        success, decrypted = tester.test_decrypt_message("bob", message_id)
        if not success:
            print("❌ Message decryption failed")
            return 1
        
        # Verify decrypted content matches sent content
        if decrypted.get('plaintext') == "Hello Bob! This is a test message from Alice.":
            print("✅ Decrypted message matches sent content")
            tester.tests_passed += 1
        else:
            print("❌ Decrypted message doesn't match sent content")
        tester.tests_run += 1

    # Test 11: Download XSD schema
    if not tester.test_xsd_schema():
        print("❌ XSD schema download failed")
        return 1

    # Test 12: Logout
    if not tester.test_logout():
        print("❌ Logout failed")
        return 1

    # Print final results
    print("\n" + "=" * 60)
    print(f"📊 Backend Tests Summary:")
    print(f"   Tests passed: {tester.tests_passed}/{tester.tests_run}")
    print(f"   Success rate: {(tester.tests_passed/tester.tests_run)*100:.1f}%")
    
    if tester.tests_passed == tester.tests_run:
        print("🎉 All backend tests passed!")
        return 0
    else:
        print("⚠️  Some backend tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())