#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import ssl
import sys
import re
from typing import Any, Dict, Iterable, List, Optional

try:
    import ldap3
    from ldap3.core.exceptions import LDAPException, LDAPBindError
except ImportError:
    print("Missing 'ldap3' package. Install with: pip install ldap3", file=sys.stderr)
    sys.exit(1)

BANNER="""                             
            ░░▒▒▒▒▒░░░░▒▒▒▒▒░░            
         ░░▒▒▒▓▓▓▒░░▓▓░░▒▓▓▓▒▒▒░░           
        ░░▒▒▓▓▓▒▒░░▓██▓░░▒▒▓▓▓▒▒░░        
     ░░▒▒▓▓▓▓▓▒▒░░▓████▓░░▒▒▓▓▓▓▓▒▒░░      
   ░░░▒▒▓▓▓▓▓▓▒▒░░▓████▓░░▒▒▓▓▓▓▓▓▒▒░░░    
   ░░░▒▒▓▓▓▓▓▓▒▒░░▓████▓░░▒▒▓▓▓▓▓▓▒▒░░░    
     ░░▒▒▓▓▓▓▓▒▒░░▓████▓░░▒▒▓▓▓▓▓▒▒░░     
      ░░░▒▒▒▓▓▓▒▒░░▓██▓░░▒▒▓▓▓▒▒▒░░░      
        ░░▒▒▒▒▓▓▒▒░░▓▓░░▒▒▓▓▒▒▒▒░░         
            ░░▒▒▒▒▒░░░░▒▒▒▒▒░░               ~One eye to bind them all~
"""

class Ldap:
    """Helper for authentication and searches in LDAP/Active Directory."""

    # Attributes we collapse to scalar if they come in a list
    SCALAR_ATTRS = {
        "name",
        "sAMAccountName",
        "distinguishedName",
        "primaryGroupID",
        "objectSid",
        "displayName",
        "title",
        "department",
        "manager",
        "adminCount",
        "info",
        "description",
        "gPLink",
        "gPOptions",
        "managedBy",
        "groupType",
    }

    ALLOWED_CONTAINERS = {
        "CN=USERS",
        "CN=COMPUTERS",
        "CN=MANAGED SERVICE ACCOUNTS",
    }

    def __init__(self, target: str, domain: str, username: str, password: str, ssl_enabled: bool = False, page_size: int = 500,) -> None:
        self.target = target
        self.domain = domain
        self.username = username
        self.password = password
        self.use_ssl = ssl_enabled
        self.page_size = page_size

        self.log = logging.getLogger(__name__)
        self.port = 636 if self.use_ssl else 389
        self.base_dn = self._get_basedn_from_domain()
        self.conn: Optional[ldap3.Connection] = None

        # True if strict LDAPS fails due to certificate and we fall back to LDAPS without verification
        self.insecure_ssl = False
        
        # LDAP request counter for statistics
        self.ldap_requests = 0

    # ---------- Context manager ----------
    def __enter__(self) -> "Ldap":
        self.conn = self.connect()
        if self.conn:
            # Discover base DN via RootDSE. If it fails, keep the domain-derived fallback
            discovered = self._discover_basedn(self.conn)
            if discovered:
                self.base_dn = discovered
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close_connection(self.conn)

    # ---------- RootDSE ----------
    def _discover_basedn(self, conn: ldap3.Connection) -> Optional[str]:
        """Read defaultNamingContext from RootDSE."""
        try:
            self.ldap_requests += 1
            self.log.debug("LDAP Request #%d: RootDSE discovery", self.ldap_requests)
            conn.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=["defaultNamingContext"],
            )
            if conn.entries and "defaultNamingContext" in conn.entries[0]:
                return conn.entries[0]["defaultNamingContext"].value
        except LDAPException:
            self.log.debug("Could not read RootDSE", exc_info=True)
        return None

    # ---------- Utilities ----------
    def _get_basedn_from_domain(self) -> str:
        """contoso.local -> DC=contoso,DC=local"""
        return ",".join(f"DC={part}" for part in self.domain.split("."))

    def _server(self) -> ldap3.Server:
        """Create the ldap3.Server object with TLS if needed."""
        tls = None
        if self.use_ssl:
            validate = ssl.CERT_NONE if self.insecure_ssl else ssl.CERT_REQUIRED
            tls = ldap3.Tls(validate=validate)
        return ldap3.Server(host=self.target, port=self.port, use_ssl=self.use_ssl, tls=tls, get_info=ldap3.NONE, connect_timeout=5,)

    def _login(self) -> ldap3.Connection:
        """Create the Connection object and bind using NTLM."""
        server = self._server()
        user = f"{self.domain}\\{self.username}"
        return ldap3.Connection(server=server, user=user, password=self.password, authentication=ldap3.NTLM, auto_bind=True, raise_exceptions=True, auto_referrals=False,)

    @staticmethod
    def _is_stronger_auth_required(exc: LDAPBindError) -> bool:
        """Inspect the result dict in LDAPBindError."""
        try:
            if exc.args and isinstance(exc.args[0], dict):
                result_dict = exc.args[0]
                code = result_dict.get("result")
                desc = (result_dict.get("description") or "").lower()
                # 8 = strongAuthRequired
                return code == 8 or desc == "strongauthrequired"
        except Exception:
            pass
        return False

    def connect(self) -> Optional[ldap3.Connection]:
        """Connect with the described fallbacks, without relying on substring matching."""
        # First attempt based on --ssl flag. 
        try:
            conn = self._login()
            self.log.info(("LDAPS" if self.use_ssl else "LDAP") + " - Login successful")
            return conn
        except ssl.SSLCertVerificationError:
            # Only reached if use_ssl=True and certificate validation fails
            self.log.warning("LDAPS (strict) failed certificate verification; trying insecure LDAPS.")
            try:
                self.insecure_ssl = True
                self.port = 636
                conn = self._login()
                self.log.info("LDAPS (insecure) - Login successful")
                return conn
            except Exception:
                self.log.warning("LDAPS (insecure) failed; trying plain LDAP as a last resort.")
                try:
                    self.use_ssl = False
                    self.insecure_ssl = False
                    self.port = 389
                    conn = self._login()
                    self.log.info("LDAP - Login successful")
                    return conn
                except Exception:
                    self.log.exception("Plain LDAP also failed")
        except LDAPBindError as exc:
            # If the server requires signing/sealing (strongAuthRequired), try LDAPS
            if self._is_stronger_auth_required(exc) and not self.use_ssl:
                self.log.warning(
                    "DC requires LDAP signing/sealing (strongAuthRequired). "
                    "Trying LDAPS (strict → insecure)."
                )
                try:
                    self.use_ssl = True
                    self.insecure_ssl = False
                    self.port = 636
                    conn = self._login()
                    self.log.info("LDAPS - Login successful")
                    return conn
                except ssl.SSLCertVerificationError:
                    self.log.warning("LDAPS (strict) failed certificate; trying insecure LDAPS.")
                    try:
                        self.insecure_ssl = True
                        conn = self._login()
                        self.log.info("LDAPS (insecure) - Login successful")
                        return conn
                    except Exception:
                        self.log.exception("LDAPS (insecure) failed after strongAuthRequired")
            else:
                self.log.exception("LDAP bind error", exc_info=True)
        except Exception:
            self.log.exception("Unexpected error during connection", exc_info=True)
        return None

    def close_connection(self, ldap_connection: Optional[ldap3.Connection]) -> None:
        """Close the connection if active."""
        try:
            if ldap_connection and ldap_connection.bound:
                ldap_connection.unbind()
                self.log.debug("LDAP connection closed")
        except Exception:
            self.log.debug("Error closing connection", exc_info=True)

    # ---------- SID helpers ----------
    @staticmethod
    def _sid_bytes_to_str(b: bytes) -> str:
        """Convert binary SID to S-1-... format."""
        if not b or len(b) < 8:
            return ""
        revision = b[0]
        sub_count = b[1]
        authority = int.from_bytes(b[2:8], byteorder="big")
        subs = []
        offset = 8
        for _ in range(sub_count):
            if offset + 4 > len(b):
                break
            subs.append(int.from_bytes(b[offset : offset + 4], byteorder="little"))
            offset += 4
        return "S-{}-{}-{}".format(revision, authority, "-".join(str(s) for s in subs))

    @staticmethod
    def _sid_str_to_bytes(s: str) -> Optional[bytes]:
        """Convert SDDL (S-1-...) to binary."""
        try:
            parts = s.strip().split("-")
            if len(parts) < 4 or parts[0].upper() != "S":
                return None
            revision = int(parts[1])
            authority = int(parts[2])
            subauths = [int(x) for x in parts[3:]]
            if not (0 <= revision <= 255):
                return None
            if len(subauths) > 255:
                return None
            res = bytearray()
            res.append(revision & 0xFF)
            res.append(len(subauths) & 0xFF)
            res.extend(int(authority).to_bytes(6, "big", signed=False))
            for sa in subauths:
                res.extend(int(sa).to_bytes(4, "little", signed=False))
            return bytes(res)
        except Exception:
            return None

    # ---------- Normalization ----------
    def _normalize(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize attributes: convert objectSid to SDDL; collapse scalars."""
        out: Dict[str, Any] = {}
        for k, v in attributes.items():
            # Convert objectSid to SDDL string
            if k == "objectSid":
                if isinstance(v, (bytes, bytearray)):
                    v = self._sid_bytes_to_str(bytes(v))
                elif isinstance(v, list) and v:
                    if isinstance(v[0], (bytes, bytearray)):
                        v = self._sid_bytes_to_str(bytes(v[0]))
                    else:
                        v = v[0]
            # Collapse known scalar attributes when they come as lists
            if k in self.SCALAR_ATTRS and isinstance(v, list):
                v = v[0] if v else None
            out[k] = v
        return out

    # ---------- Search ----------
    def search(self, ldap_connection: ldap3.Connection, ldap_filter: str, attributes: Iterable[str], search_base: Optional[str] = None, search_scope=ldap3.SUBTREE,) -> List[Dict[str, Any]]:
        """Paged searches + normalization."""
        try:
            self.ldap_requests += 1
            self.log.debug("LDAP Request #%d: Search filter=%s, attrs=%s", self.ldap_requests, ldap_filter, list(attributes))
            
            entry_generator = ldap_connection.extend.standard.paged_search(
                search_base=search_base or self.base_dn,
                search_filter=ldap_filter,
                search_scope=search_scope,
                attributes=list(attributes),
                paged_size=self.page_size,
                generator=True,
            )

            normalized_results: List[Dict[str, Any]] = []
            total_entries = 0
            for entry in entry_generator:
                if entry.get("type") != "searchResEntry":
                    continue
                normalized_entry = self._normalize(entry.get("attributes", {}))
                normalized_results.append(normalized_entry)
                total_entries += 1

            if not normalized_results:
                self.log.debug("LDAP search returned no results")
            else:
                self.log.debug("Retrieved %d objects (page_size=%d)", total_entries, self.page_size)
            return normalized_results

        except LDAPException:
            self.log.exception("Error during LDAP search")
            return []

    # ---------- Base read (DN exact) ----------
    def base_read(self, conn: ldap3.Connection, dn: str, attrs: Iterable[str]) -> Optional[Dict[str, Any]]:
        """BASE read on the given DN with arbitrary attributes."""
        try:
            self.ldap_requests += 1
            self.log.debug("LDAP Request #%d: BASE read DN=%s, attrs=%s", self.ldap_requests, dn, list(attrs))
            
            conn.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=list(attrs),
            )
            if not conn.entries:
                return None
            raw = {a: conn.entries[0][a].value for a in attrs if a in conn.entries[0]}
            return self._normalize(raw)
        except LDAPException:
            self.log.debug("base_read failed for %s", dn, exc_info=True)
            return None

    # ---------- Script-specific helpers ----------

    @staticmethod
    def _looks_like_dn(value: str) -> bool:
        """Check if a string looks like a DN (Distinguished Name)."""
        v = value.strip()
        if "=" not in v or "," not in v:
            return False
        start = v.split(",", 1)[0].strip().upper()
        return start.startswith(("CN=", "OU=", "DC="))

    def get_object_by_dn(self, conn: ldap3.Connection, dn: str) -> Optional[Dict[str, Any]]:
        """Try a BASE read on the given DN (generic object: user/computer/MSA/FSP/etc.)."""
        attrs = [
            "distinguishedName",
            "description",
            "sAMAccountName",
            "name",
            "primaryGroupID",
            "objectSid",
            # user extras (if applicable)
            "displayName",
            "title",
            "department",
            "manager",
            "adminCount",
            "info",
        ]
        return self.base_read(conn, dn, attrs)

    def get_parent_groups_for_dn(self, conn: ldap3.Connection, dn: str) -> List[Dict[str, Any]]:
        """Return all groups (including nested) for a DN."""
        escaped_dn = ldap3.utils.conv.escape_filter_chars(dn)
        ldap_filter = f"(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={escaped_dn}))"
        attrs = [
            "name",
            "sAMAccountName",
            "description",
            "distinguishedName",
            # extras
            "managedBy",
            "info",
            "groupType",
        ]
        return self.search(conn, ldap_filter, attrs)

    def _search_group_by_sid_any(self, conn: ldap3.Connection, sid_sddl: str) -> Optional[Dict[str, Any]]:
        """Search a group by SID trying SDDL first, else escaped binary."""
        attrs = ["name", "sAMAccountName", "description", "distinguishedName", "managedBy", "info", "groupType"]

    # 1) Direct SDDL
        esc_sid = ldap3.utils.conv.escape_filter_chars(sid_sddl)
        results = self.search(conn, f"(&(objectClass=group)(objectSid={esc_sid}))", attrs)
        if results:
            return results[0]

    # 2) Escaped binary
        sid_bytes = self._sid_str_to_bytes(sid_sddl)
        if sid_bytes:
            esc_bin = ldap3.utils.conv.escape_bytes(sid_bytes)
            results = self.search(conn, f"(&(objectClass=group)(objectSid={esc_bin}))", attrs)
            if results:
                return results[0]
        return None

    def resolve_primary_group_by_sid(
        self,
        conn: ldap3.Connection,
        user_sid: str,
        primary_gid: str,
    ) -> Optional[Dict[str, Any]]:
        """Resolve primary group by SID (domain SID + primaryGroupID)."""
        try:
            base_sid = "-".join(user_sid.split("-")[:-1])
            group_sid = f"{base_sid}-{int(primary_gid)}"
        except Exception:
            self.log.debug("Could not build primary group's SID", exc_info=True)
            return None

        obj = self._search_group_by_sid_any(conn, group_sid)
        if obj:
            return obj
        return None

    def get_principal(self, conn: ldap3.Connection, identifier: str, ptype: str) -> Optional[Dict[str, Any]]:
        """Get an AD object by type/identifier."""
        esc_id = ldap3.utils.conv.escape_filter_chars(identifier)
        attrs_common = [
            "distinguishedName",
            "description",
            "sAMAccountName",
            "name",
            "primaryGroupID",
            "objectSid",
            # user extras (if applicable)
            "displayName",
            "title",
            "department",
            "manager",
            "adminCount",
            "info",
        ]

        def _with_dollar(x: str) -> str:
            return x if x.endswith("$") else x + "$"

        if ptype == "user":
            ldap_filter = f"(&(objectCategory=Person)(objectClass=user)(sAMAccountName={esc_id}))"
            attrs = attrs_common
        elif ptype == "computer":
            sam = _with_dollar(identifier)
            esc_sam = ldap3.utils.conv.escape_filter_chars(sam)
            ldap_filter = f"(&(objectCategory=Computer)(objectClass=computer)(sAMAccountName={esc_sam}))"
            attrs = attrs_common
        elif ptype == "msa":
            sam = _with_dollar(identifier)
            esc_sam = ldap3.utils.conv.escape_filter_chars(sam)
            ldap_filter = f"(&(objectClass=msDS-ManagedServiceAccount)(sAMAccountName={esc_sam}))"
            attrs = attrs_common
        elif ptype == "gmsa":
            sam = _with_dollar(identifier)
            esc_sam = ldap3.utils.conv.escape_filter_chars(sam)
            ldap_filter = f"(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName={esc_sam}))"
            attrs = attrs_common
        elif ptype == "fsp":
            # SID o CN
            if identifier.upper().startswith("S-"):
                # 1) SDDL
                esc_sid = ldap3.utils.conv.escape_filter_chars(identifier)
                ldap_filter = f"(&(objectClass=foreignSecurityPrincipal)(objectSid={esc_sid}))"
                attrs = ["distinguishedName", "description", "name", "objectSid"]
                results = self.search(conn, ldap_filter, attrs)
                if results:
                    return results[0]
                # 2) Escaped binary
                sid_bytes = self._sid_str_to_bytes(identifier)
                if sid_bytes:
                    esc_bin = ldap3.utils.conv.escape_bytes(sid_bytes)
                    ldap_filter = f"(&(objectClass=foreignSecurityPrincipal)(objectSid={esc_bin}))"
                    results = self.search(conn, ldap_filter, attrs)
                    return results[0] if results else None
                return None
            else:
                ldap_filter = f"(&(objectClass=foreignSecurityPrincipal)(cn={esc_id}))"
                attrs = ["distinguishedName", "description", "name", "objectSid"]
        else:
            self.log.error("Unsupported type: %s", ptype)
            return None

        results = self.search(conn, ldap_filter, attrs)
        return results[0] if results else None

    def get_principal_auto(self, conn: ldap3.Connection, identifier: str) -> Optional[Dict[str, Any]]:
        """Get an AD object by auto-detected type (DN, SID, sAMAccountName)."""
        ident = identifier.strip()

    # 0) Try DN (BASE) only if it looks like a DN.
        if self._looks_like_dn(ident):
            obj = self.get_object_by_dn(conn, ident)
            if obj:
                return obj

    # 1) SID -> try all object types
        if ident.upper().startswith("S-"):
            # Try users first (most common)
            for obj_class in [
                ("user", "(&(objectCategory=Person)(objectClass=user))"),
                ("computer", "(&(objectCategory=Computer)(objectClass=computer))"),
                ("group", "(&(objectClass=group))"),
                ("msa", "(&(objectClass=msDS-ManagedServiceAccount))"),
                ("gmsa", "(&(objectClass=msDS-GroupManagedServiceAccount))"),
                ("fsp", "(&(objectClass=foreignSecurityPrincipal))")
            ]:
                try:
                    # 1) Direct SDDL
                    esc_sid = ldap3.utils.conv.escape_filter_chars(ident)
                    base_filter = obj_class[1][:-1]  # Remove closing )
                    ldap_filter = f"{base_filter}(objectSid={esc_sid}))"
                    attrs = [
                        "distinguishedName", "description", "sAMAccountName", "name",
                        "primaryGroupID", "objectSid", "displayName", "title", 
                        "department", "manager", "adminCount", "info"
                    ]
                    results = self.search(conn, ldap_filter, attrs)
                    if results:
                        return results[0]
                    
                    # 2) Escaped binary
                    sid_bytes = self._sid_str_to_bytes(ident)
                    if sid_bytes:
                        esc_bin = ldap3.utils.conv.escape_bytes(sid_bytes)
                        ldap_filter = f"{base_filter}(objectSid={esc_bin}))"
                        results = self.search(conn, ldap_filter, attrs)
                        if results:
                            return results[0]
                except Exception:
                    continue
            return None

    # 2) If it ends with $, try gMSA/MSA/Computer
        if ident.endswith("$"):
            for t in ("gmsa", "msa", "computer"):
                obj = self.get_principal(conn, ident, t)
                if obj:
                    return obj

    # 3) Attempts by sAMAccountName: user -> computer (in case $ was omitted) -> msa -> gmsa
        for t in ("user", "computer", "msa", "gmsa"):
            obj = self.get_principal(conn, ident, t)
            if obj:
                return obj

    # 4) FSP by CN (when they pass the CN of the FSP)
        return self.get_principal(conn, ident, "fsp")

    # ---------- DN / OU helpers ----------
    @staticmethod
    def dn_key(d: Dict[str, Any]) -> str:
        """Get a normalized DN key for a dictionary."""
        return (d.get("distinguishedName") or "").lower()

    def add_with_parents(self, conn: ldap3.Connection, start_dn: str, groups: List[Dict[str, Any]], known: Dict[str, Dict[str, Any]], ) -> None:
        """Add parent groups of a given DN to a list, avoiding duplicates."""
        parents = self.get_parent_groups_for_dn(conn, start_dn)
        for item in parents:
            k = self.dn_key(item)
            if k and k not in known:
                groups.append(item)
                known[k] = item

    def ancestors_ou_or_container(self, dn: str) -> List[str]:
        """
        Return the chain from the object upwards including OUs and certain containers.
        E.g.: CN=Alice,OU=Dept,OU=Users,DC=contoso,DC=local ->
              ['OU=Dept,OU=Users,DC=contoso,DC=local', 'OU=Users,DC=contoso,DC=local']
        Includes common containers (CN=Users, CN=Computers, CN=Managed Service Accounts).
        """
        out: List[str] = []
        cur = dn.strip()
        while True:
            if "," not in cur:
                break
            # Current RDN
            rdn, rest = cur.split(",", 1)
            rdn_u = rdn.strip().upper()
            if rdn_u.startswith("OU=") or rdn_u in self.ALLOWED_CONTAINERS:
                out.append(cur)
            cur = rest
        return out

    def get_display_name_for_dn(self, conn: ldap3.Connection, dn: str) -> Optional[str]:
        """Return a friendly name for a DN (displayName > name > sAMAccountName)."""
        attrs = ["displayName", "name", "sAMAccountName"]
        obj = self.base_read(conn, dn, attrs)
        if not obj:
            return None
        return obj.get("displayName") or obj.get("name") or obj.get("sAMAccountName")

    # ---------- GPO helpers ----------
    @staticmethod
    def parse_gplink(gplink: Optional[str]) -> List[Dict[str, Any]]:
        """
        Parse gPLink into a list of dicts: [{"ref": "<DN or GUID>", "flags": int}, ...]
        Typical gPLink: [LDAP://CN={GUID},CN=Policies,CN=System,DC=...;0][LDAP://CN={GUID2},...;2]
        """
        if not gplink:
            return []
        out: List[Dict[str, Any]] = []
        for ref, flags in re.findall(r"\[LDAP://([^;]+);(\d+)\]", gplink):
            out.append({"ref": ref.strip(), "flags": int(flags)})
        return out

    def _gpo_dn_from_ref(self, ref: str) -> str:
        """
        Normalize a gPLink reference to a GPO DN.
        - If 'ref' already starts with CN= -> assume it's the GPO DN.
        - If 'ref' looks like a GUID (with or without braces), build CN={GUID},CN=Policies,CN=System,<base_dn>
        """
        if ref.upper().startswith("CN="):
            return ref
        guid = ref.strip()
        if not (guid.startswith("{") and guid.endswith("}")):
            guid = "{" + guid.strip("{}") + "}"
        return f"CN={guid},CN=Policies,CN=System,{self.base_dn}"

    def read_gpo(self, conn: ldap3.Connection, gpo_dn: str) -> Optional[Dict[str, Any]]:
        attrs = ["displayName", "description", "gPCFileSysPath", "versionNumber", "distinguishedName", "name"]
        return self.base_read(conn, gpo_dn, attrs)


# ---------- CLI ----------

def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Fast Active Directory context enumeration for newly obtained credentials. "
        )
    )
    p.add_argument("--domain", "-d", required=True, help="Domain (e.g., contoso.local)")
    p.add_argument("--user", "-u", required=True, help="Username (name only; DOMAIN\\user will be formed)")
    p.add_argument("--password", "-p", required=True, help="Password for NTLM authentication")
    p.add_argument("-dc", required=True, help="Domain Controller or IP (LDAP server)")
    p.add_argument(
        "-x",
        dest="identifier",
        required=True,
        help="Target object identifier (auto-detected): sAMAccountName (user.admin), computer name with/without $ (fileserver$), Distinguished Name, or SID (for FSPs)",
    )

    # Connection (minimal)
    p.add_argument("--ssl", action="store_true", help="Prefer LDAPS (port 636). Auto-fallback: strict → insecure → LDAP (389) if needed")

    # Misc
    p.add_argument("-s", action="store_true", help="Enable silent mode (no banner)")
    p.add_argument("--debug", action="store_true", help="Enable DEBUG-level logging")
    return p.parse_args(argv)


def main(argv: List[str]) -> int:

    if "-h" in argv or "--help" in argv or not '-s' in argv:
        print(BANNER)
    #print(BANNER)
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    log = logging.getLogger("sauron")

    client = Ldap(target=args.dc, domain=args.domain, username=args.user, password=args.password, ssl_enabled=args.ssl, )

    try:
        with client as c:
            if not c.conn or not c.conn.bound:
                log.error("Could not establish LDAP connection (NTLM credentials)")
                return 2

            # 1) Get the object by auto-detecting type (with DN BASE attempt first)
            obj = c.get_principal_auto(c.conn, args.identifier)
            if not obj:
                log.error(f"No object found with identifier '{args.identifier}'")
                return 3

            dn = obj.get("distinguishedName") or ""
            desc = obj.get("description")
            sam = obj.get("sAMAccountName")
            display_name = obj.get("displayName")
            title = obj.get("title")
            department = obj.get("department")
            manager_dn = obj.get("manager")
            admin_count = obj.get("adminCount")
            info_notes = obj.get("info")
            primary_gid = obj.get("primaryGroupID")
            user_sid = obj.get("objectSid")

            manager_name = None
            if manager_dn:
                try:
                    manager_name = c.get_display_name_for_dn(c.conn, manager_dn)
                except Exception:
                    log.debug("Could not resolve manager DN", exc_info=True)

            # 2) Groups (including nested)
            groups: List[Dict[str, Any]] = []
            known_groups: Dict[str, Dict[str, Any]] = {}
            c.add_with_parents(c.conn, dn, groups, known_groups)

            # 3) Primary group (with fallback 513/515/516) and its parent groups
            if primary_gid and user_sid:
                try:
                    pg = c.resolve_primary_group_by_sid(c.conn, str(user_sid), str(primary_gid))
                    if not pg:
                        # Fallback for common groups if SID/token resolution doesn't work
                        fallback_map = {
                            "513": "Domain Users",
                            "515": "Domain Computers",
                            "516": "Domain Controllers",
                        }
                        name = fallback_map.get(str(primary_gid))
                        if name:
                            # These built-in groups typically live under CN=Users
                            dn_fb = f"CN={name},CN=Users,{c.base_dn}"
                            pg = {
                                "sAMAccountName": name,
                                "name": name,
                                "description": "",
                                "distinguishedName": dn_fb,
                            }
                    if pg:
                        k = c.dn_key(pg)
                        if k and k not in known_groups:
                            groups.append(pg)
                            known_groups[k] = pg
                        c.add_with_parents(c.conn, pg.get("distinguishedName") or "", groups, known_groups)
                except Exception:
                    log.debug("Could not resolve primary group", exc_info=True)

            # Stable sort
            def _key(x: Dict[str, Any]) -> str:
                return (x.get("sAMAccountName") or x.get("name") or "").lower()

            groups_sorted = sorted(groups, key=_key)

            # 4) OUs/containers for the object and each group (plus ancestors)
            ou_dns_all: Dict[str, Dict[str, Any]] = {}
            # for the object
            for ou_dn in c.ancestors_ou_or_container(dn):
                ou_dns_all[ou_dn.lower()] = {"dn": ou_dn}
            # for the groups
            for g in groups_sorted:
                g_dn = g.get("distinguishedName") or ""
                for ou_dn in c.ancestors_ou_or_container(g_dn):
                    ou_dns_all[ou_dn.lower()] = {"dn": ou_dn}

            # 5) Read attributes of each OU/container and collect GPOs
            ou_info_map: Dict[str, Dict[str, Any]] = {}
            gpo_links_per_ou: Dict[str, List[Dict[str, Any]]] = {}
            gpo_cache: Dict[str, Dict[str, Any]] = {}  # keyed by GPO DN

            for ouk, ou_entry in ou_dns_all.items():
                ou_dn = ou_entry["dn"]
                try:
                    ou_obj = c.base_read(
                        c.conn,
                        ou_dn,
                        ["distinguishedName", "name", "description", "gPLink", "gPOptions"],
                    )
                    if not ou_obj:
                        continue
                    ou_info_map[ouk] = ou_obj

                    # Parse gPLink
                    refs = c.parse_gplink(ou_obj.get("gPLink"))
                    gpo_resolved_list: List[Dict[str, Any]] = []
                    for r in refs:
                        gpo_dn = c._gpo_dn_from_ref(r["ref"])
                        gpo_dn_l = gpo_dn.lower()
                        if gpo_dn_l not in gpo_cache:
                            gpo_obj = c.read_gpo(c.conn, gpo_dn)
                            if gpo_obj:
                                gpo_cache[gpo_dn_l] = gpo_obj
                        gpo = gpo_cache.get(gpo_dn_l)
                        if gpo:
                            gpo_resolved_list.append({
                                "gpo": gpo,
                                "flags": r["flags"],  # leave flags as-is (we don't interpret bits here)
                            })
                    gpo_links_per_ou[ouk] = gpo_resolved_list
                except Exception:
                    log.debug("Failed to read OU/container %s", ou_dn, exc_info=True)

            # Output legible
            def _fmt_multival(val):
                if isinstance(val, list):
                    return " | ".join(str(v) for v in val)
                return val or ""

            print("Object:")
            if sam:
                print(f"  sAMAccountName: {sam}")
            if display_name and display_name != sam:
                print(f"  DisplayName: {display_name}")
            print(f"  DN: {dn}")
            print(f"  Description: {_fmt_multival(desc)}")
            if info_notes:
                print(f"  Notes (info): {_fmt_multival(info_notes)}")
            if title:
                print(f"  Title: {_fmt_multival(title)}")
            if department:
                print(f"  Department: {_fmt_multival(department)}")
            if manager_dn:
                mgr_line = manager_dn
                if manager_name:
                    mgr_line += f"  ({manager_name})"
                print(f"  Manager: {mgr_line}")
            if admin_count is not None:
                print(f"  adminCount: {admin_count}")
            if primary_gid:
                print(f"  primaryGroupID: {primary_gid}")
            if user_sid:
                print(f"  objectSid: {user_sid}")
            print()

            # Groups
            if not groups_sorted:
                print("Groups: (none)")
            else:
                print("Groups (including nested and primary group if applicable):")
                for g in groups_sorted:
                    g_name = g.get("sAMAccountName") or g.get("name") or "(no name)"
                    g_desc = _fmt_multival(g.get("description"))
                    g_dn = g.get("distinguishedName") or ""
                    print(f"  - {g_name}")
                    if g_desc:
                        print(f"      Description: {g_desc}")
                    if g.get("info"):
                        print(f"      Notes (info): {_fmt_multival(g.get('info'))}")
                    if g.get("managedBy"):
                        print(f"      managedBy: {g.get('managedBy')}")
                    if g.get("groupType") is not None:
                        log.debug(f"      groupType: {g.get('groupType')}")
                    if g_dn:
                        print(f"      DN: {g_dn}")
                print()

            # OUs / Containers
            if not ou_info_map:
                print("OUs/Containers: (none)")
            else:
                print("OUs/Containers (for the object and its groups, including ancestors):")
                # Maintaining approximate order: closest first (not strictly guaranteed)
                for ouk, ou_obj in ou_info_map.items():
                    ou_dn = ou_obj.get("distinguishedName") or ouk
                    print(f"  - {ou_dn}")
                    if ou_obj.get("name"):
                        print(f"      Name: {ou_obj.get('name')}")
                    if ou_obj.get("description"):
                        print(f"      Description: {_fmt_multival(ou_obj.get('description'))}")
                    if ou_obj.get("gPOptions") is not None:
                        print(f"      gPOptions: {ou_obj.get('gPOptions')}")
                    # GPOs linked to this OU/container
                    gpos = gpo_links_per_ou.get(ouk, [])
                    if not gpos:
                        log.debug(f"      GPO Links: (none)")
                    else:
                        print(f"      GPO Links:")
                        for link in gpos:
                            gpo = link["gpo"]
                            flags = link["flags"]
                            gpo_name = gpo.get("displayName") or gpo.get("name") or "(no name)"
                            gpo_dn = gpo.get("distinguishedName") or ""
                            print(f"        * {gpo_name}")
                            if gpo.get("description"):
                                print(f"            Description: {_fmt_multival(gpo.get('description'))}")
                            if gpo.get("gPCFileSysPath"):
                                print(f"            SYSVOL Path: {gpo.get('gPCFileSysPath')}")
                            if gpo.get("versionNumber") is not None:
                                print(f"            versionNumber: {gpo.get('versionNumber')}")
                            print(f"            DN: {gpo_dn}")
                            print(f"            gPLink flags: {flags}")
                print()

            return 0

    except Exception:
        log.exception("Unexpected failure")
        return 1
    finally:
        # Show LDAP request statistics in debug mode
        if args.debug and client.ldap_requests > 0:
            log.info("LDAP Statistics: %d total requests made", client.ldap_requests)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
