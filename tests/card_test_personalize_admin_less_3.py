"""
card_test_personalize_admin_less_3.py - test admin-less mode

Copyright (C) 2022  g10 Code GmbH
Author: NIIBE Yutaka <gniibe@fsij.org>

This file is a part of Gnuk, a GnuPG USB Token implementation.

Gnuk is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Gnuk is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from struct import pack
from re import match, DOTALL
from util import *
from card_const import *
from constants_for_test import *

class Test_Card_Personalize_Adminless_SECOND(object):
    # Being removed keys, it's now in admin-full mode (both of Gnuk 1 and 2)

    def test_setup_pw3_1(self, card):
        if card.is_gnuk2:
            r = card.change_passwd(3, FACTORY_PASSPHRASE_PW3, PW3_TEST0)
            assert r
        else:
            pytest.skip("Gnuk 1 now in admin-full mode, with PW3_TEST0")

    def test_verify_pw3_1(self, card):
        if card.is_gnuk2:
            r = card.verify(3, PW3_TEST0)
            assert r
        else:
            pytest.skip("Gnuk 1, it's authenticated already")

    def test_reset_userpass_admin(self, card):
        r = card.reset_passwd_by_admin(PW1_TEST4)
        assert r
