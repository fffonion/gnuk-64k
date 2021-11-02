import pytest

@pytest.fixture(scope="module",autouse=True)
def check_yubikey(card):
    if card.is_yubikey:
        pytest.skip("Yubikey has no support for those features", allow_module_level=True)
