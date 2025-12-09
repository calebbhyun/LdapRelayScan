#!/usr/bin/env python3

import urllib.parse
import ldap3
import argparse
import sys
import ssl
import socket
import getpass
import asyncio

from msldap.connection import MSLDAPClientConnection
from msldap.commons.factory import LDAPConnectionFactory


def run_ldaps_noEPA(inputUser, inputPassword, dcTarget):
    """
    LDAPS bind with NO channel binding (EPA disabled).
    Determines whether channel binding is required.
    """
    try:
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        ldapServer = ldap3.Server(dcTarget, use_ssl=True, port=636, tls=tls)
        ldapConn = ldap3.Connection(
            ldapServer, user=inputUser, password=inputPassword, authentication=ldap3.NTLM
        )

        if not ldapConn.bind():
            r = str(ldapConn.result)
            if "data 80090346" in r:
                return True
            elif "data 52e" in r:
                return False
            else:
                print("UNEXPECTED ERROR:", r)
        else:
            return False

    except Exception as e:
        print(f"[!] LDAPS no-EPA error on {dcTarget}: {e}")
        return None


async def run_ldaps_withEPA(inputUser, inputPassword, dcTarget, timeout):
    """
    LDAPS bind WITH intentionally invalid channel binding data.
    Determines whether CB is required when supported.
    """
    try:
        inputPassword = urllib.parse.quote(inputPassword)
        url = f"ldaps+ntlm-password://{inputUser}:{inputPassword}@{dcTarget}"

        conn_url = LDAPConnectionFactory.from_url(url)
        ldaps_client = conn_url.get_client()
        ldaps_client.target.timeout = timeout

        conn = MSLDAPClientConnection(ldaps_client.target, ldaps_client.creds)
        _, err = await conn.connect()
        if err:
            raise err

        conn.cb_data = b"\x00" * 73
        _, err = await conn.bind()

        if "data 80090346" in str(err):
            return True
        elif "data 52e" in str(err):
            return False
        elif err:
            print(f"[!] LDAPS EPA error: {err}")
            return None
        else:
            return False

    except Exception as e:
        print(f"[!] LDAPS with-EPA exception: {e}")
        return None


def DoesLdapsCompleteHandshake(dcIp):
    """
    Test LDAPS TLS handshake
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    ssl_sock = ssl.wrap_socket(s, cert_reqs=ssl.CERT_OPTIONAL)

    try:
        ssl_sock.connect((dcIp, 636))
        ssl_sock.do_handshake()
        ssl_sock.close()
        return True
    except Exception as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            return True
        return False


def run_ldap(inputUser, inputPassword, dcTarget):
    """
    LDAP bind → determine if LDAP Signing is enforced
    """
    ldapServer = ldap3.Server(dcTarget, use_ssl=False, port=389)
    ldapConn = ldap3.Connection(
        ldapServer, user=inputUser, password=inputPassword, authentication=ldap3.NTLM
    )

    if not ldapConn.bind():
        r = str(ldapConn.result)
        if "stronger" in r:
            return True
        elif "data 52e" in r or "data 532" in r:
            print("[!] Invalid credentials - aborting.")
            sys.exit(1)
        else:
            print("UNEXPECTED ERROR:", r)
            return None
    else:
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Check LDAP & LDAPS NTLM relay protections on a single DC."
    )

    parser.add_argument("-method", choices=["LDAPS", "BOTH"], default="LDAPS")
    parser.add_argument("-dc-ip", required=True, help="DC IP or hostname.")
    parser.add_argument("-d", "--domain", required=True, help="Domain.")
    parser.add_argument("-u", "--username", required=True, help="Username.")
    parser.add_argument("-p", "--password", default="defaultpass", help="Password.")
    parser.add_argument("-nthash", help="NT hash.")
    parser.add_argument("-timeout", type=int, default=10)

    opt = parser.parse_args()

    dc = opt.dc_ip
    username = opt.domain + "\\" + opt.username
    password = opt.password

    if opt.method == "BOTH":
        if opt.nthash:
            password = "aad3b435b51404eeaad3b435b51404ee:" + opt.nthash
        elif password == "defaultpass":
            password = getpass.getpass("Password: ")

    print(f"\n[+] Targeting DC: {dc}")
    print(f"[+] Using NTLM identity: {username}")

    # LDAP signing check
    if opt.method == "BOTH":
        ldap_signing = run_ldap(username, password, dc)
        if ldap_signing is False:
            print(" [+] LDAP SIGNING NOT ENFORCED! (relay possible)")
        elif ldap_signing is True:
            print(" [-] LDAP signing enforced.")
        else:
            print(" [!] Unable to determine LDAP signing.")

    # LDAPS channel binding check
    print("\n[+] Checking LDAPS Channel Binding…")

    if DoesLdapsCompleteHandshake(dc):
        noEPA = run_ldaps_noEPA(username, password, dc)
        withEPA = asyncio.run(run_ldaps_withEPA(username, password, dc, opt.timeout))

        if noEPA is False and withEPA is False:
            print(' [+] LDAPS CB set to "NEVER" → RELAYABLE')
        elif noEPA is False and withEPA is True:
            print(' [-] LDAPS CB set to "WHEN SUPPORTED"')
        elif noEPA is True:
            print(' [-] LDAPS CB set to "REQUIRED"')
        else:
            print("[!] Unable to determine LDAPS channel binding.")
    else:
        print(" [!] LDAPS handshake failed (no LDAPS or blocked).")

    print()
