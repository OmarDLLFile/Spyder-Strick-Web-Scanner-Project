import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from tests.fixtures.test_app import start


@pytest.fixture(scope="session")
def app_server():
    server = start(0)
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
