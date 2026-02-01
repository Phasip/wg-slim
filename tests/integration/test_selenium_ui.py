"""Selenium UI tests driving a real browser via Selenium WebDriver.

Tests use the browser for interactions and do not use the requests library.
Requires selenium and webdriver-manager.
"""

import os
import pytest
import threading
import time
import signal
import shutil
import json
import urllib.parse
from unittest.mock import patch, MagicMock

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.common.exceptions import WebDriverException
from selenium.common.exceptions import StaleElementReferenceException

from webdriver_manager.chrome import ChromeDriverManager
import uvicorn
import wg_api
from conftest import free_port_tcp

assert "requests" not in globals(), "Do not import requests in this module; use Selenium for browser interactions."


class WireGuardAPI:
    """Test helper that exposes a minimal ASGI app with a `.run()` helper.

    Placed under `tests/` because it's only used by tests and keeps test
    helpers separate from production modules.
    """

    def __init__(self, config_file=None):
        sync_service = type(
            "_TestMockSync",
            (),
            {
                "get_sync_status": lambda self: {"running": False, "sync_count": 0, "last_error": None, "last_error_time": None},
                "sync_now": lambda self: None,
            },
        )()

        app = wg_api.create_app(config_file=config_file, sync_service=sync_service)

        self.app = app
        self.fastapi_app = app

    def run(self, host: str = "127.0.0.1", port: int = 8000):
        uvicorn.run(self.app, host=host, port=port, log_level="info")


def create_test_config(tmpdir):
    """Create a test config file."""
    config_content = """basic:
  password: testpassword123
  bind_addr: "5000"

server:
  name: server
  interface_name: wg0
  interface: |
    Address = 10.0.0.1/24
    ListenPort = 51820
    PrivateKey = WEkjVLbCGf8hShZ0ZGMpTHvXhCKt+myLRGneVFnNqk4=
    DNS = 1.1.1.1
  as_peer: |
    PublicKey = aFcrala5TI5GAAS5kNwXg1YR+jPkKVB8WchLQqzfyG8=
    Endpoint = vpn.example.com:51820
    AllowedIPs = 0.0.0.0/0

peers:
  - name: test-peer
    interface: |
      Address = 10.0.0.2/32
      PrivateKey = WEkjVLbCGf8hShZ0ZGMpTHvXhCKt+myLRGneVFnNqk4=
      DNS = 1.1.1.1
    as_peer: |
      PublicKey = aFcrala5TI5GAAS5kNwXg1YR+jPkKVB8WchLQqzfyG8=
      AllowedIPs = 10.0.0.2/32
"""
    config_path = os.path.join(tmpdir, "config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


class TimeoutError(Exception):
    pass


def timeout_handler(signum, frame):
    """Signal handler used with signal.alarm that raises TimeoutError."""
    raise TimeoutError("Operation timed out")


def get_chrome_driver(timeout_seconds=30):
    """Get a Chrome WebDriver with headless options."""

    chromedriver = shutil.which("chromedriver")

    options = ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")

    options.set_capability("goog:loggingPrefs", {"browser": "ALL", "performance": "ALL"})

    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout_seconds)

    try:
        if not chromedriver:
            chromedriver = ChromeDriverManager().install()

        service = ChromeService(executable_path=chromedriver)
        driver = webdriver.Chrome(service=service, options=options)

        signal.alarm(0)
        return driver
    except TimeoutError:
        pytest.fail(f"Chrome WebDriver initialization timed out after {timeout_seconds}s. This usually means webdriver-manager is trying to download ChromeDriver. Check your internet connection or install ChromeDriver manually.")
    except WebDriverException as e:
        signal.alarm(0)
        pytest.fail(f"Chrome WebDriver not available: {e}")
    except Exception as e:
        signal.alarm(0)
        pytest.fail(f"Failed to initialize Chrome WebDriver: {type(e).__name__}: {e}")
    finally:
        signal.signal(signal.SIGALRM, old_handler)


def _extract_urls_from_performance_logs(perf_logs):
    """Return list of URLs observed in Chrome performance logs (Network.requestWillBeSent)."""
    urls = []
    for entry in perf_logs:
        msg = json.loads(entry["message"])["message"]
        if msg.get("method") == "Network.requestWillBeSent":
            params = msg.get("params", {})
            request = params.get("request", {})
            url = request.get("url")
            if url:
                urls.append(url)
    return urls


class ASGITestServer:
    """Context manager to run the ASGI test server in a background thread."""

    def __init__(self, config_path, port):
        self.config_path = config_path
        self.port = port
        self.app = None
        self.thread = None
        self.mock_patcher = None

    def __enter__(self):
        self.mock_patcher = patch("wg_manager.WgManager")
        MockWgManager = self.mock_patcher.start()

        mock_manager = MagicMock()
        mock_manager.is_interface_up.return_value = True
        mock_manager.interface = "wg0"

        stats_obj = MagicMock()
        peer_stat = MagicMock()
        peer_stat.public_key = "aFcrala5TI5GAAS5kNwXg1YR+jPkKVB8WchLQqzfyG8="
        peer_stat.allowed_ips = ["10.0.0.2/32"]
        stats_obj.peers = [peer_stat]
        mock_manager.get_interface_stats.return_value = stats_obj
        MockWgManager.return_value = mock_manager

        api = WireGuardAPI(
            config_file=self.config_path,
        )
        self.app = api.app
        self.api = api

        self.thread = threading.Thread(target=lambda: api.run(host="127.0.0.1", port=self.port))
        self.thread.daemon = True
        self.thread.start()

        time.sleep(1)

        return f"http://127.0.0.1:{self.port}"

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.mock_patcher:
            self.mock_patcher.stop()


@pytest.fixture
def test_config(tmp_path):
    """Create a temporary test config."""
    return create_test_config(str(tmp_path))


@pytest.fixture
def browser():
    """Get a Selenium WebDriver."""
    driver = get_chrome_driver()
    yield driver
    driver.quit()


@pytest.fixture
def unauth_session(browser, server):
    """Return an unauthenticated session as (browser, server)."""
    return browser, server


@pytest.fixture
def logged_in_session(unauth_session):
    """Return a logged-in browser using the UI for authentication.

    Uses the unauth_session fixture and performs the UI login flow.
    """
    browser, server = unauth_session
    browser_login_via_form(browser, server)
    return browser


def browser_login_via_form(browser, server, password="testpassword123"):
    """Perform a login using the UI form (no network requests library)."""
    browser.get(f"{server}/login")
    password_input = WebDriverWait(browser, 5).until(EC.presence_of_element_located((By.ID, "password")))
    password_input.clear()
    password_input.send_keys(password)
    submit_btn = browser.find_element(By.CSS_SELECTOR, "button[type='submit']")
    submit_btn.click()
    WebDriverWait(browser, 10).until(EC.url_contains("/dashboard"))


@pytest.fixture
def server(test_config):
    """Start a test ASGI server."""
    with ASGITestServer(test_config, port=free_port_tcp()) as url:
        yield url


class TestLoginPage:
    """Tests for the login page."""

    def test_login_page_loads(self, unauth_session):
        """Test that the login page loads correctly."""
        browser, server = unauth_session
        browser.get(f"{server}/login")

        assert "Login" in browser.title or "WireGuard" in browser.title

        password_input = browser.find_element(By.ID, "password")
        assert password_input is not None
        assert password_input.get_attribute("type") == "password"

        submit_btn = browser.find_element(By.CSS_SELECTOR, "button[type='submit']")
        assert submit_btn is not None

    def test_login_with_correct_password(self, unauth_session):
        """Test successful login with correct password."""
        browser, server = unauth_session
        browser_login_via_form(browser, server)

    def test_login_with_wrong_password(self, unauth_session):
        """Test failed login with wrong password."""
        browser, server = unauth_session
        browser.get(f"{server}/login")

        password_input = browser.find_element(By.ID, "password")
        password_input.send_keys("wrongpassword")

        submit_btn = browser.find_element(By.CSS_SELECTOR, "button[type='submit']")
        submit_btn.click()

        time.sleep(1)

        assert "/login" in browser.current_url or browser.current_url.endswith("/login")

        page_source = browser.page_source.lower()
        assert "invalid" in page_source or "error" in page_source or "danger" in page_source

    def test_redirect_to_login_when_not_authenticated(self, unauth_session):
        """Unauthenticated /dashboard redirects to /login."""
        browser, server = unauth_session
        browser.get(f"{server}/dashboard")

        WebDriverWait(browser, 5).until(EC.url_contains("/login"))

        assert "/login" in browser.current_url

    def test_root_redirect_and_login(self, unauth_session):
        """Visit `/`, get redirected to `/login`, submit form, reach `/dashboard`."""
        browser, server = unauth_session
        browser.get(f"{server}/")
        WebDriverWait(browser, 5).until(EC.url_contains("/login"))

        assert "/login" in browser.current_url or browser.current_url.endswith("/login")

        browser_login_via_form(browser, server)
        assert "/dashboard" in browser.current_url


class TestDashboard:
    """Tests for the dashboard page."""

    def test_dashboard_shows_peers(self, logged_in_session):
        """Test that dashboard shows peer cards."""
        WebDriverWait(logged_in_session, 40).until(EC.presence_of_element_located((By.CLASS_NAME, "card")))

        page_source = logged_in_session.page_source.lower()
        assert "peer-item" in page_source

    def test_peer_ip_visible(self, logged_in_session):
        """Dashboard shows peer IP/address for peers configured in YAML."""
        WebDriverWait(logged_in_session, 5).until(EC.presence_of_element_located((By.ID, "peers-container")))

        page_source = logged_in_session.page_source
        assert "10.0.0.2" in page_source, "Expected peer IP '10.0.0.2' to be visible on the dashboard"

    def test_logout(self, logged_in_session):
        """Test logout functionality."""
        logout_btn = logged_in_session.find_element(By.ID, "btn-logout")
        logout_btn.click()

        WebDriverWait(logged_in_session, 5).until(lambda drv: drv.execute_script("return (localStorage.getItem('wg_access_token') || sessionStorage.getItem('wg_access_token')) === null"))
        token_val = logged_in_session.execute_script("return localStorage.getItem('wg_access_token') || sessionStorage.getItem('wg_access_token')")
        assert token_val is None


class TestJavaScriptConsole:
    """Tests for JavaScript console errors."""

    def test_no_console_errors_on_login_and_dashboard(self, logged_in_session):
        """Test that no JavaScript errors appear in the console after login."""
        time.sleep(2)

        logs = logged_in_session.get_log("browser")
        non_info_logs = [log for log in logs if log["level"] != "INFO"]
        if non_info_logs:
            error_messages = "\n".join([f"  - {log['level']}: {log['message']}" for log in non_info_logs])
            pytest.fail(f"JavaScript console errors detected:\n{error_messages}")


class TestNoRemoteResources:
    """Ensure no remote (non-localhost) resources are fetched during login and dashboard."""

    def test_no_remote_resources_on_login_and_dashboard(self, unauth_session):
        browser, server = unauth_session
        browser.get(f"{server}/login")
        time.sleep(1)

        browser_login_via_form(browser, server)

        perf_logs = browser.get_log("performance")
        urls = _extract_urls_from_performance_logs(perf_logs)
        host = urllib.parse.urlparse(server).hostname
        remote_urls = [u for u in urls if urllib.parse.urlparse(u).hostname != host]

        assert not remote_urls, f"Remote resources fetched: {remote_urls}"


class TestLogsModal:
    """Tests for the logs modal."""

    def test_logs_modal_opens(self, logged_in_session):
        """Test that logs modal can be opened."""
        logs_btn = WebDriverWait(logged_in_session, 5).until(EC.element_to_be_clickable((By.CSS_SELECTOR, "[data-bs-target='#logsModal']")))
        logs_btn.click()

        modal = WebDriverWait(logged_in_session, 5).until(EC.visibility_of_element_located((By.ID, "logsModal")))

        assert modal.is_displayed()

        logs_container = logged_in_session.find_element(By.ID, "logs-container")
        assert logs_container is not None

    def test_logs_modal_refresh(self, logged_in_session):
        """Test that logs can be refreshed."""
        logs_btn = WebDriverWait(logged_in_session, 5).until(EC.element_to_be_clickable((By.CSS_SELECTOR, "[data-bs-target='#logsModal']")))
        logs_btn.click()

        WebDriverWait(logged_in_session, 5).until(EC.visibility_of_element_located((By.ID, "logsModal")))

        refresh_btn = logged_in_session.find_element(By.ID, "btn-refresh-logs")
        refresh_btn.click()

        time.sleep(1)

        logs_container = logged_in_session.find_element(By.ID, "logs-container")
        assert logs_container is not None


class TestSettingsModal:
    """Tests for the settings modals."""

    def test_change_password_modal_opens(self, logged_in_session):
        """Test that change password modal can be opened."""
        change_pwd_btn = WebDriverWait(logged_in_session, 5).until(EC.element_to_be_clickable((By.CSS_SELECTOR, "[data-bs-target='#changePasswordModal']")))
        change_pwd_btn.click()

        modal = WebDriverWait(logged_in_session, 5).until(EC.visibility_of_element_located((By.ID, "changePasswordModal")))

        assert modal.is_displayed()

        current_pwd = logged_in_session.find_element(By.ID, "current-password")
        new_pwd = logged_in_session.find_element(By.ID, "new-password")
        confirm_pwd = logged_in_session.find_element(By.ID, "confirm-password")
        assert current_pwd is not None
        assert new_pwd is not None
        assert confirm_pwd is not None


class TestPeerManagement:
    """Tests for peer management operations in the dashboard."""

    def _get_peer_badge_text(self, browser, peer_name):
        """Return the peer's badge text, or an empty string if unavailable."""

        try:
            peer_btn = browser.find_element(By.CSS_SELECTOR, f"[data-peer='{peer_name}']")
            peer_card = peer_btn.find_element(By.XPATH, "./ancestor::div[contains(@class, 'card')]")
            badge = peer_card.find_element(By.CSS_SELECTOR, ".badge")
            return badge.text
        except StaleElementReferenceException:
            return ""

    def _wait_for_badge_text(self, browser, peer_name, expected_text, timeout=5):
        """Wait until the badge contains the expected text."""

        def check_badge():
            try:
                text = self._get_peer_badge_text(browser, peer_name)
                return expected_text in text
            except StaleElementReferenceException:
                return False

        WebDriverWait(browser, timeout).until(lambda d: check_badge())

    def test_toggle_peer_disable(self, logged_in_session):
        """Test that a peer can be disabled via the toggle button."""
        WebDriverWait(logged_in_session, 5).until(EC.presence_of_element_located((By.CLASS_NAME, "card")))

        toggle_btn = WebDriverWait(logged_in_session, 5).until(EC.element_to_be_clickable((By.CSS_SELECTOR, "[data-action='toggle-enabled'][data-peer='test-peer']")))

        self._wait_for_badge_text(logged_in_session, "test-peer", "Enabled")

        toggle_btn.click()

        self._wait_for_badge_text(logged_in_session, "test-peer", "Disabled")

        assert "Disabled" in self._get_peer_badge_text(logged_in_session, "test-peer")

    def test_toggle_peer_enable(self, logged_in_session):
        """Test that a disabled peer can be re-enabled."""
        WebDriverWait(logged_in_session, 5).until(EC.presence_of_element_located((By.CLASS_NAME, "card")))

        toggle_btn = WebDriverWait(logged_in_session, 5).until(EC.element_to_be_clickable((By.CSS_SELECTOR, "[data-action='toggle-enabled'][data-peer='test-peer']")))

        toggle_btn.click()

        self._wait_for_badge_text(logged_in_session, "test-peer", "Disabled")

        toggle_btn = WebDriverWait(logged_in_session, 5).until(EC.element_to_be_clickable((By.CSS_SELECTOR, "[data-action='toggle-enabled'][data-peer='test-peer']")))
        toggle_btn.click()

        self._wait_for_badge_text(logged_in_session, "test-peer", "Enabled")

        assert "Enabled" in self._get_peer_badge_text(logged_in_session, "test-peer")

    def test_toggle_peer_no_js_errors(self, logged_in_session):
        """Test that toggling peer enabled/disabled doesn't produce JS errors."""
        WebDriverWait(logged_in_session, 5).until(EC.presence_of_element_located((By.CLASS_NAME, "card")))

        toggle_btn = WebDriverWait(logged_in_session, 5).until(EC.element_to_be_clickable((By.CSS_SELECTOR, "[data-action='toggle-enabled'][data-peer='test-peer']")))
        toggle_btn.click()

        time.sleep(1)

        logs = logged_in_session.get_log("browser")

        errors = [log for log in logs if log["level"] == "SEVERE"]
        critical_errors = [log for log in errors if "favicon" not in log["message"].lower() and "net::ERR" not in log["message"]]

        if critical_errors:
            error_messages = "\n".join([f"  - {log['message']}" for log in critical_errors])
            pytest.fail(f"JavaScript console errors detected when toggling peer:\n{error_messages}")
