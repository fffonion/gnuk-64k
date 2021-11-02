"""
card_test_public_key_operations.py - test the sign/dec/auth

Copyright (C) 2021  g10 Code GmbH
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

class Test_Card_PK_OPs(object):
    def test_sign_0(self, card, pk):
        digestinfo = pk.compute_digestinfo(pk.test_vector['sign_0'])
        sig = card.cmd_pso(0x9e, 0x9a, digestinfo)
        r = pk.key_list[0].verify_signature(digestinfo, sig)
        assert r

    def test_sign_1(self, card, pk):
        digestinfo = pk.compute_digestinfo(pk.test_vector['sign_1'])
        sig = card.cmd_pso(0x9e, 0x9a, digestinfo)
        r = pk.key_list[0].verify_signature(digestinfo, sig)
        assert r

    def test_decrypt_0(self, card, pk):
        encrypted_data = pk.key_list[1].encrypt(pk.test_vector['decrypt_0'])
        r = card.cmd_pso(0x80, 0x86, pk.enc_data(encrypted_data))
        assert pk.enc_check(encrypted_data, r)

    def test_decrypt_1(self, card, pk):
        encrypted_data = pk.key_list[1].encrypt(pk.test_vector['decrypt_1'])
        r = card.cmd_pso(0x80, 0x86, pk.enc_data(encrypted_data))
        assert pk.enc_check(encrypted_data, r)

    def test_auth_0(self, card, pk):
        digestinfo = pk.compute_digestinfo(pk.test_vector['auth_0'])
        sig = card.cmd_internal_authenticate(digestinfo)
        r = pk.key_list[2].verify_signature(digestinfo, sig)
        assert r

    def test_auth_1(self, card, pk):
        digestinfo = pk.compute_digestinfo(pk.test_vector['auth_1'])
        sig = card.cmd_internal_authenticate(digestinfo)
        r = pk.key_list[2].verify_signature(digestinfo, sig)
        assert r
