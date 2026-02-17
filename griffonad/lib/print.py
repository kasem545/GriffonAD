import os
import binascii
import time
import re
import shutil
import textwrap
from colorama import Back, Fore, Style
from jinja2 import Template, Environment, FileSystemLoader

import griffonad.lib.consts as c
import griffonad.lib.actions
import griffonad.config
from griffonad.lib.actions import *
from griffonad.lib.database import Owned, Database
from griffonad.lib.ml import MiniLanguage
from griffonad.lib.utils import sanityze_symbol, password_to_nthash


COMMENT_RE = re.compile(r"^(#.*)$", re.MULTILINE)

ACTION_DETECTIONS = {
    "::ForceChangePassword": {
        "events": "4724, 4738",
        "safer": "::AddKeyCredentialLink",
    },
    "::DCSync": {"events": "4662, 4670", "safer": "::AddKeyCredentialLink"},
    "::AddMember": {"events": "4728, 4732, 4756", "safer": "::AddKeyCredentialLink"},
    "::WriteSPN": {"events": "5136", "safer": "::AddKeyCredentialLink"},
    "::EnableNP": {"events": "4738, 5136", "safer": "::Kerberoasting"},
    "::AddKeyCredentialLink": {"events": "5136", "safer": "N/A"},
    "::WriteGPLink": {"events": "5136", "safer": "::AddKeyCredentialLink"},
    "::DaclFullControl": {"events": "4662, 4670", "safer": "targeted DACL right"},
}

ACTION_CLEANUP = {
    "::AddMember": "Remove added group member and verify group ACL consistency",
    "::WriteSPN": "Restore original SPN set on target account",
    "::EnableNP": "Re-enable pre-auth requirement on target account",
    "::AddKeyCredentialLink": "Delete injected KeyCredential from msDS-KeyCredentialLink",
    "::WriteGPLink": "Remove malicious gPLink entry from target OU",
    "::DaclFullControl": "Restore original object DACL from backup",
    "::DaclDCSync": "Remove granted DCSync ACEs from domain root",
    "::DaclWriteGPLink": "Remove WriteGPLink ACE from OU ACL",
}

DACL_ABUSE_MATRIX = {
    "user": {
        "WriteDacl": [
            "reset-password",
            "shadow-credentials",
            "spn-injection",
            "script-path-abuse",
        ],
        "GenericAll": ["takeover", "credential-reset", "shadow-credentials"],
        "WriteOwner": ["become-owner-then-dacl"],
        "Owns": ["dacl-rewrite"],
    },
    "computer": {
        "WriteDacl": ["rbcd", "shadow-credentials", "full-control"],
        "GenericAll": ["rbcd", "secretsdump-path"],
        "WriteOwner": ["become-owner-then-dacl"],
    },
    "group": {
        "WriteDacl": ["add-member", "add-self"],
        "GenericAll": ["group-takeover"],
        "WriteOwner": ["become-owner-then-dacl"],
    },
    "ou": {
        "WriteDacl": ["write-gplink", "full-control"],
        "GenericWrite": ["write-gplink"],
        "WriteOwner": ["become-owner-then-dacl"],
    },
    "gpo": {
        "WriteDacl": ["gpo-takeover"],
        "GenericWrite": ["immediate-task", "logon-script", "local-admin"],
    },
    "domain": {
        "WriteDacl": ["grant-dcsync", "full-control"],
        "AllExtendedRights": ["dcsync"],
        "GetChanges_GetChangesAll": ["dcsync"],
    },
    "dc": {
        "WriteDacl": ["shadow-credentials", "full-control"],
        "GenericWrite": ["shadow-credentials"],
        "AdminTo": ["secretsdump-path"],
    },
}


def color1_object(o: LDAPObject, underline=False) -> str:
    if o is None:
        return "many"
    if underline:
        u = Style.UNDERLINE
    else:
        u = ""
    sid = o.sid.replace(o.from_domain + "-", "")
    if sid in c.BUILTIN_SID:
        name = "BUILTIN\\" + o.name.upper()
    else:
        name = o.name.upper()
    if o.is_admin:
        return f"{u}{Fore.RED}♦{name}{Style.RESET_ALL}"
    if o.can_admin:
        return f"{u}{Fore.YELLOW}★{name}{Style.RESET_ALL}"
    return f"{u}{name}{Style.RESET_ALL}"


def color2_object(o: LDAPObject, underline=False) -> str:
    if o is None:
        return "many"
    if underline:
        u = Style.UNDERLINE
    else:
        u = ""
    if o.sid in c.BUILTIN_SID:
        name = "BUILTIN\\" + name.upper()
    else:
        name = o.name.upper()
    if o.is_admin:
        return f"{u}{Fore.RED}♦{name}{Style.RESET_ALL}"
    if o.can_admin:
        return f"{u}{Fore.YELLOW}★{name}{Style.RESET_ALL}"
    return f"{u}{Fore.GREEN}{name}{Style.RESET_ALL}"


def set_attr(obj, name, value):
    if name == "secret":
        value = red(value)
    setattr(obj, name, value)
    return ""


def red(s):
    return f"{Fore.RED}{s}{Style.RESET_ALL}"


def _color_tag(text: str, color: str) -> str:
    return f"{color}{text}{Style.RESET_ALL}"


def _term_width() -> int:
    try:
        return shutil.get_terminal_size((120, 20)).columns
    except Exception:
        return 120


def _wrap_items(
    prefix: str, items: list[str], indent: int = 4, width: int | None = None
):
    if width is None:
        width = _term_width()
    if not items:
        return
    body = ", ".join(items)
    initial = " " * indent + prefix
    subsequent = " " * (indent + len(prefix))
    for line in textwrap.wrap(
        body, width=width, initial_indent=initial, subsequent_indent=subsequent
    ):
        print(line)


def _sev_label(sev: str) -> str:
    if sev == "critical":
        return _color_tag("CRITICAL", Fore.RED)
    if sev == "high":
        return _color_tag("HIGH", Fore.YELLOW)
    if sev == "medium":
        return _color_tag("MEDIUM", Fore.GREEN)
    return _color_tag("LOW", Fore.CYAN)


RIGHT_SEVERITY = {
    "GetChanges_GetChangesAll": "critical",
    "GetChanges_GetChangesInFilteredSet": "critical",
    "DCSync": "critical",
    "GenericAll": "critical",
    "WriteDacl": "critical",
    "WriteOwner": "critical",
    "Owns": "critical",
    "AllExtendedRights": "high",
    "AdminTo": "high",
    "AddKeyCredentialLink": "high",
    "AllowedToAct": "high",
    "AllowedToDelegate": "high",
    "WriteGPLink": "high",
    "AddMember": "high",
    "ForceChangePassword": "high",
    "SeBackupPrivilege": "high",
    "ReadLAPSPassword": "medium",
    "ReadGMSAPassword": "medium",
    "WriteSPN": "medium",
    "WriteUserAccountControl": "medium",
    "SetLogonScript": "medium",
    "HasPrivSession": "high",
    "HasSession": "medium",
    "SessionForUser": "low",
    "PrivSessionForUser": "medium",
    "TrustedDomain": "low",
    "TrustedDomainPivot": "medium",
    "ADCS_ESC1": "high",
    "ADCS_ESC2": "high",
    "ADCS_ESC3": "high",
    "ADCS_ESC4": "high",
}


def color_right_name(name: str) -> str:
    sev = RIGHT_SEVERITY.get(name, "low")
    if sev == "critical":
        return _color_tag(name, Fore.RED)
    if sev == "high":
        return _color_tag(name, Fore.YELLOW)
    if sev == "medium":
        return _color_tag(name, Fore.GREEN)
    return _color_tag(name, Fore.CYAN)


def color_action_name(name: str) -> str:
    if name.startswith("::"):
        base = name
        sev = "medium"
        key = name[2:]
        if key.startswith("ADCS_ESC") or key in ["DCSync", "DaclFullControl"]:
            sev = "critical"
        elif key in [
            "AddKeyCredentialLink",
            "ForceChangePassword",
            "AddMember",
            "WriteGPLink",
            "AllowedToAct",
            "AllowedToDelegate",
        ]:
            sev = "high"
        elif key in ["ReadLAPSPassword", "ReadGMSAPassword", "WriteSPN", "EnableNP"]:
            sev = "medium"
        else:
            sev = "low"

        if sev == "critical":
            return _color_tag(base, Fore.RED)
        if sev == "high":
            return _color_tag(base, Fore.YELLOW)
        if sev == "medium":
            return _color_tag(base, Fore.GREEN)
        return _color_tag(base, Fore.CYAN)
    return name


tmpl_path = os.path.dirname(os.path.abspath(__file__)) + "/../templates"
env = Environment(
    loader=FileSystemLoader(tmpl_path),
    trim_blocks=True,
    lstrip_blocks=True,
)
env.filters["red"] = red


# High value targets
def print_hvt(args, db: Database):
    print()
    print(
        f"{Fore.RED}♦{Style.RESET_ALL} admin | {Fore.YELLOW}★{Style.RESET_ALL} path-to-admin | {Style.UNDERLINE}owned{Style.RESET_ALL}"
    )
    print()
    print("badges:")
    print(
        f"{Fore.GREEN}A{Style.RESET_ALL}  admincount is set (this flag doesn't tell that the user is an admin, it could be an old admin)"
    )
    print(
        f"{Fore.GREEN}K{Style.RESET_ALL}  the user may be Kerberoastable (at least one SPN is set)"
    )
    print(f"{Fore.GREEN}N{Style.RESET_ALL}  DONT_REQUIRE_PREAUTH (ASREPRoastable)")
    print(f"{Fore.GREEN}P{Style.RESET_ALL}  the user is in the Protected group")
    print(
        f"{Fore.GREEN}!R{Style.RESET_ALL} PASSWORD_NOTREQUIRED (it means the password can be empty)"
    )
    print(f"{Fore.GREEN}S{Style.RESET_ALL}  SENSITIVE")
    print(
        f"{Fore.GREEN}T{Style.RESET_ALL}  TRUSTED_TO_AUTH_FOR_DELEGATION (it means you can impersonate to admin in constrained delegations)"
    )
    print(f"{Fore.GREEN}!X{Style.RESET_ALL} DONT_EXPIRE_PASSWORD")
    print()

    def print_user(o):
        owned = o.name.upper() in db.owned_db
        print(color1_object(o, underline=owned), end="")

        if o.admincount:
            print(f"{Fore.GREEN} A{Style.RESET_ALL}", end="")
        if o.spn and o.type != c.T_COMPUTER and o.name.upper() != "KRBTGT":
            print(f"{Fore.GREEN} K{Style.RESET_ALL}", end="")
        if o.np:
            print(f"{Fore.GREEN} N{Style.RESET_ALL}", end="")
        if o.protected:
            print(f"{Fore.GREEN} P{Style.RESET_ALL}", end="")
        if o.passwordnotreqd:
            print(f"{Fore.GREEN} !R{Style.RESET_ALL}", end="")
        if o.sensitive:
            print(f"{Fore.GREEN} S{Style.RESET_ALL}", end="")
        if o.trustedtoauth:
            print(f"{Fore.GREEN} T{Style.RESET_ALL}", end="")
        if o.pwdneverexpires:
            print(f"{Fore.GREEN} !X{Style.RESET_ALL}", end="")

        if args.sid:
            print(f" {Fore.BLACK}{o.sid}{Style.RESET_ALL}", end="")

        print()

        if not o.can_admin and not o.is_admin:
            for sid, rights in o.rights_by_sid.items():
                if "RestrictedGroups" in rights:
                    print(
                        f"    {Fore.BLACK}note: RestrictedGroups not expanded for admin inference{Style.RESET_ALL}"
                    )
                    break

        for sid in o.group_sids:
            if sid == "many":
                name = "many"
            elif sid not in db.objects_by_sid:
                name = f"UNKNOWN_{sid}"
            else:
                name = color1_object(db.objects_by_sid[sid])
            print(f"    < {name}")

        for sid, rights in o.rights_by_sid.items():
            if sid == "many":
                target_name = "many"
            elif sid not in db.objects_by_sid:
                target_name = f"UNKNOWN_{sid}"
            else:
                target_name = color1_object(db.objects_by_sid[sid])
            for r in rights.keys():
                if rights[r] is not None:
                    print(f"    {color_right_name(r)}({rights[r]} -> {target_name})")
                else:
                    print(f"    {color_right_name(r)}({target_name})")

        print()

    admins = []
    pivots = []
    others = []
    for o in db.iter_users():
        if args.select and not o.name.upper().startswith(args.select.upper()):
            continue
        if o.is_admin:
            admins.append(o)
        elif o.can_admin:
            pivots.append(o)
        else:
            others.append(o)

    if admins:
        print(_color_tag(f"Admins ({len(admins)})", Fore.RED))
        print()
        for o in admins:
            print_user(o)

    if pivots:
        print(_color_tag(f"\nPaths-to-admin ({len(pivots)})", Fore.YELLOW))
        print()
        for o in pivots:
            print_user(o)

    if others:
        print(_color_tag(f"\nOther ({len(others)})", Fore.CYAN))
        print()
        for o in others:
            print_user(o)

    print()


def print_ous(args, db: Database):
    print()
    names = []
    for dn in db.ous_by_dn.keys():
        ou = db.objects_by_sid[db.ous_dn_to_sid[dn]]
        if not args.select or ou.name.upper().startswith(args.select.upper()):
            names.append(ou.name.upper())
    names.sort()

    for name in names:
        ou = db.objects_by_name[name]
        data = db.ous_by_dn[ou.dn]

        if not data["members"] and not data["gpo_links"]:
            continue

        print(ou.dn, end="")

        if args.sid:
            print(f" {Fore.BLACK}{ou.sid}{Style.RESET_ALL}", end="")

        print()

        if data["gpo_links"]:
            for sid in data["gpo_links"]:
                print("  <=>", color1_object(db.objects_by_sid[sid]))

        if data["members"]:
            print(f"    {len(data['members'])} members")
            if args.members:
                for sid in data["members"]:
                    if sid not in db.objects_by_sid:
                        name = f"UNKNOWN_{sid}"
                    else:
                        name = color1_object(db.objects_by_sid[sid])
                    print("   ", name)

        print()


def print_groups(args, db: Database):
    protected_group = f"{db.domain.sid}-525"
    print()

    names = []
    for sid in db.groups_by_sid.keys():
        g = db.objects_by_sid[sid]
        if not args.select or g.name.upper().startswith(args.select.upper()):
            names.append(g.name.upper())
    names.sort()

    printed = False

    for name in names:
        g = db.objects_by_name[name]
        members = db.groups_by_sid[g.sid]

        # always print the protected group
        if g.sid != protected_group and not g.rights_by_sid:
            continue

        printed = True

        sid = g.sid.replace(g.from_domain + "-", "")

        print(f"{color1_object(g)}", end="")

        if args.sid:
            print(f" {Fore.BLACK}{g.sid}{Style.RESET_ALL}", end="")

        print()

        if members:
            print(f"    {len(members)} members")
            if args.members:
                for m in members:
                    print("   ", color1_object(db.objects_by_sid[m]))

        for sid, rights in g.rights_by_sid.items():
            if sid == "many":
                name = "many"
            elif sid not in db.objects_by_sid:
                name = f"UNKNOWN_{sid}"
            else:
                name = color1_object(db.objects_by_sid[sid])
            for i, r in enumerate(rights.keys()):
                if rights[r] is not None:
                    print(f"    ({color_right_name(r)}, {rights[r]} -> {name})")
                else:
                    print(f"    ({color_right_name(r)}, {name})")

    if args.select and not printed:
        print("This group may not have interesting rights")

    print()


def print_paths(args, db: Database, paths: list):
    def score_path(path):
        opsec = 0
        blast = 0
        for _, sym, target, _ in path:
            if sym in ["::DCSync", "::DaclFullControl", "::ForceChangePassword"]:
                opsec += 40
                blast += 30
            elif sym in ["::AddMember", "::WriteSPN", "::EnableNP", "::WriteGPLink"]:
                opsec += 25
                blast += 20
            elif sym in [
                "::AddKeyCredentialLink",
                "::AllowedToAct",
                "::AllowedToDelegate",
            ]:
                opsec += 15
                blast += 15

            if target is not None and getattr(target, "is_admin", False):
                blast += 15

        return opsec, blast

    if paths:
        if args.score_paths:
            paths.sort(key=lambda p: score_path(p))
        print()
        found_path_to_admin = False
        for i, p in enumerate(paths):
            if not args.da or p[-1][2].is_admin and args.da:
                print("%0.3x " % i, end="")
            last_is_admin = p[-1][2] is not None and p[-1][2].is_admin
            if last_is_admin:
                print(f"{Fore.WHITE}{Back.RED}+{Style.RESET_ALL}", end=" ")
            elif not args.da:
                print("  ", end="")
            if not args.da or last_is_admin and args.da:
                if args.score_paths:
                    opsec, blast = score_path(p)
                    print(f"[opsec={opsec:03d} blast={blast:03d}] ", end="")
                print_path(args, p)
                print()
    else:
        print("[+] No paths found :(")


def print_path(args, path: list):
    length = len(path)
    end = " —> "
    i = 0

    while i < length:
        if i == length - 1:
            end = ""

        parent, symbol, target, required = path[i]

        if parent is not None:
            parent_name = color2_object(parent.obj)
            print(f"{parent_name}", end=end)

        # If the target changes multiple times before an apply or a stop, only the
        # final target will be displayed

        # Print all actions and requires until an apply or a stop
        while True:
            par, sym, tar, req = path[i]

            if sym in c.TERMINALS:
                break

            if args.rights:
                if sym[:2] not in ["__", "::"]:
                    print(f"{color_right_name(sym)},", end="")
            else:
                if sym.startswith("::") and sym[2] != "_":
                    print(f"{color_action_name(sym)}", end="")

                if req is not None:
                    print(f"[{req['class_name']}]", end="")

            i += 1

        target_name = color2_object(target)
        print(f"({target_name}):", end="")

        # don't print apply* and stop keywords
        if sym in c.TERMINALS:
            i += 1

    parent, symbol, target, required = path[i - 1]
    target_name = color2_object(target)
    print(f"{target_name}")


def render_template(filename, **kwargs):
    template = env.get_template(filename)
    out = template.render(**kwargs)
    out = COMMENT_RE.sub(rf"{Fore.BLUE}\1{Style.RESET_ALL}", out)
    print(out)
    print()


def print_script(args, db: Database, path: list):
    glob = {
        "fqdn": db.domain.name,
        "fqdn_lower": db.domain.name.lower(),
        "domain_short_name": db.domain.name.split(".")[0],
        "dc_name": db.main_dc.name.replace("$", ""),
        "dc_ip": args.dc_ip,
        "domain_sid": db.domain.sid,
        "spn": "random/spn",
        "plain": "PLAIN_PASSWORD_HEX",
        "connectback_ip": f"CONNECTBACK_IP",
        "DEFAULT_PASSWORD": griffonad.config.DEFAULT_PASSWORD,
        "T_SECRET_PASSWORD": c.T_SECRET_PASSWORD,
        "T_SECRET_NTHASH": c.T_SECRET_NTHASH,
        "T_SECRET_AESKEY": c.T_SECRET_AESKEY,
        "T_COMPUTER": c.T_COMPUTER,
        "T_USER": c.T_USER,
        "T_DC": c.T_DC,
        "T_MANY": c.T_MANY,
        "T_OU": c.T_OU,
        "T_DOMAIN": c.T_DOMAIN,
        "T_CONTAINER": c.T_CONTAINER,
        "T_GROUP": c.T_GROUP,
        "T_GPO": c.T_GPO,
        "password_to_nthash": password_to_nthash,
        "set_attr": set_attr,
    }
    glob["mydomain"] = f"arbitrary.{glob['fqdn_lower']}"

    print_comment(
        [
            "You may need to add these lines to your /etc/hosts:",
            f"{glob['dc_ip']} {glob['dc_name']}.{glob['fqdn']}",
            f"{glob['dc_ip']} {glob['dc_name']}",
        ]
    )

    if glob["dc_ip"] == "DC_IP":
        print_comment("Use the option --dc-ip to set DC_IP!")

    last_target = None
    last_parent = None

    previous_action = ""

    for parent, symbol, target, require in path:
        if (
            last_target is not None
            and target is not None
            and target.name != last_target.name
        ):
            print(f"{Fore.YELLOW}{last_target.name} is owned{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Next target is {target.name}{Style.RESET_ALL}")
            print()

        if (
            target is not None
            and last_target is not None
            and last_target.sid != target.sid
            and target.sid in db.users
        ):
            diff = time.time() - target.lastlogon
            if target.lastlogon == -1:
                print_warning(f"{target.name} never logged, is it a honey pot?\n")
            elif diff > 60 * 60 * 24 * 30 * 6:
                print_warning(
                    f"{target.name} lastlogon > 6 months, is it a honey pot?\n"
                )

        if target is None:
            last_target = None
        else:
            last_target = target

        if parent is None:
            last_parent = None
        else:
            if last_parent is not None and last_parent.krb_auth and not parent.krb_auth:
                print_cmd("unset KRB5CCNAME\n")
                last_parent.krb_auth = False
            last_parent = parent

        if parent is not None and not parent.krb_auth:
            nopass = None
            if parent.obj.protected:
                print_comment(f"{parent.obj.name} is protected, switch to kerberos")
                nopass = False
            elif parent.secret_type == c.T_SECRET_PASSWORD and parent.secret == "":
                print_comment(
                    f"PASSWORD_NOTREQUIRED: the password may be blank, it's easier to get a TGT first"
                )
                nopass = True
            if nopass is not None:
                render_template(
                    "_TGTRequest.jinja2",
                    parent=parent,
                    T_SECRET_PASSWORD=c.T_SECRET_PASSWORD,
                    T_SECRET_AESKEY=c.T_SECRET_AESKEY,
                    T_SECRET_NTHASH=c.T_SECRET_NTHASH,
                    dc_ip=glob["dc_ip"],
                    fqdn=glob["fqdn"],
                    set_attr=set_attr,
                    nopass=nopass,
                )

        if require is not None:
            class_name = sanityze_symbol(require["class_name"])
            griffonad.lib.require.__getattribute__(class_name).print(
                glob, parent, require
            )

        if symbol.startswith("::"):
            # Print commands, we will create a new owned object if we have a full control on it

            v = {
                "previous_action": previous_action,
                "require": require,
            }

            if parent is not None:
                v["parent"] = parent
                v["parent_no_dollar"] = parent.obj.name.replace("$", "")
                v["parent_ip"] = f"{parent.obj.name.replace('$', '')}_IP"

            if target is not None:
                v["target"] = target
                v["target_no_dollar"] = target.name.replace("$", "")
                v["target_ip"] = f"{target.name.replace('$', '')}_IP"

            if parent is not None and target is not None:
                if parent.krb_need_fqdn:
                    v["target_no_dollar"] += f".{glob['fqdn']}"

            v.update(glob)

            s = sanityze_symbol(symbol)[2:]
            render_template(f"{s}.jinja2", **v)

        previous_action = symbol


def print_desc(db: Database):
    for o in db.objects_by_sid.values():
        if o.description is not None and o.description.strip():
            if o.type not in [c.T_GPO, c.T_CONTAINER, c.T_OU]:
                rid = int(o.sid.split("-")[-1])
                do_print = rid >= 1000
            else:
                do_print = True

            if do_print:
                if o.type in [c.T_USER, c.T_COMPUTER]:
                    print(color2_object(o))
                else:
                    print(color1_object(o))
                print("   ", o.description)


def print_trusts(args, db: Database):
    print()
    found = False
    for o in db.objects_by_sid.values():
        if o.type != c.T_DOMAIN:
            continue
        if not hasattr(o, "trusts") or not o.trusts:
            continue
        found = True
        print(color1_object(o))
        for tr in o.trusts:
            target = tr["name"]
            direction = tr["direction_name"]
            trust_type = tr["type"]
            transitive = "transitive" if tr["is_transitive"] else "non-transitive"
            sid_filtering = tr["sid_filtering_enabled"]
            if sid_filtering is None:
                sid_filtering_txt = "SIDFiltering:unknown"
            elif sid_filtering:
                sid_filtering_txt = "SIDFiltering:on"
            else:
                sid_filtering_txt = "SIDFiltering:off"
            print(
                f"    -> {target} ({direction}, {trust_type}, {transitive}, {sid_filtering_txt})"
            )
            if tr["abuse_paths"]:
                abuse = ", ".join(
                    [_color_tag(a, Fore.YELLOW) for a in tr["abuse_paths"]]
                )
                print(f"       abuse: {abuse}")
        print()

    if not found:
        print("No trusts found in collected data")
        print()


def _score_user(db: Database, o):
    score = 0
    reasons = []
    laps_targets = set()
    gmsa_targets = set()

    weights = {
        "DCSync": 120,
        "ReadLAPSPassword": 65,
        "ReadGMSAPassword": 60,
        "AddKeyCredentialLink": 50,
        "AllowedToAct": 45,
        "AllowedToDelegate": 45,
        "ForceChangePassword": 40,
        "AdminTo": 35,
        "SeBackupPrivilege": 35,
        "WriteDacl": 28,
        "GenericAll": 25,
    }

    for target_sid, rights in o.rights_by_sid.items():
        target = db.objects_by_sid.get(target_sid, None)
        target_name = target.name if target is not None else target_sid

        for right in rights.keys():
            if right in weights:
                score += weights[right]
                reasons.append(right)

            if right == "ReadLAPSPassword":
                laps_targets.add(target_name)
            elif right == "ReadGMSAPassword":
                gmsa_targets.add(target_name)
            elif right == "HasPrivSession":
                score += 35
                reasons.append("PrivSession")
            elif right == "HasSession":
                score += 12
                reasons.append("Session")

    if o.np:
        score += 15
        reasons.append("ASREPRoastable")

    if o.spn and o.type == c.T_USER and o.name.upper() != "KRBTGT":
        score += 12
        reasons.append("Kerberoastable")

    if o.passwordnotreqd:
        score += 20
        reasons.append("BlankPassword")

    return score, sorted(set(reasons)), sorted(laps_targets), sorted(gmsa_targets)


def print_priorities(args, db: Database):
    entries = []
    for o in db.iter_users():
        if args.select and not o.name.upper().startswith(args.select.upper()):
            continue
        score, reasons, laps_targets, gmsa_targets = _score_user(db, o)
        if score <= 0:
            continue
        entries.append((score, o, reasons, laps_targets, gmsa_targets))

    entries.sort(key=lambda item: (-item[0], item[1].name.upper()))

    print()
    print("Priority score (higher means faster path to privileged creds or control)")
    print()

    if not entries:
        print("No prioritized opportunities found")
        print()
        return

    for i, entry in enumerate(entries[:25], 1):
        score, o, reasons, laps_targets, gmsa_targets = entry
        name = color1_object(o, underline=o.name.upper() in db.owned_db)
        print(f"{i:02d}. score={score:03d} {name}")
        if laps_targets:
            print(
                f"    LAPS targets ({len(laps_targets)}): {', '.join(laps_targets[:4])}"
            )
        if gmsa_targets:
            print(
                f"    gMSA targets ({len(gmsa_targets)}): {', '.join(gmsa_targets[:4])}"
            )
        if reasons:
            print(f"    reasons: {', '.join(reasons[:8])}")
        print()


def print_dacl_matrix(args, db: Database):
    print()
    print("DACL abuse matrix (reachable primitives)")
    print()

    rows = []
    for o in db.iter_users():
        if args.select and not o.name.upper().startswith(args.select.upper()):
            continue

        for target_sid, rights in o.rights_by_sid.items():
            target = db.objects_by_sid.get(target_sid)
            if target is None:
                continue

            target_type = c.ML_TYPES_TO_STR.get(target.type, "unknown")
            matrix = DACL_ABUSE_MATRIX.get(target_type, {})
            if not matrix:
                continue

            abuses = set()
            used = []
            for right in rights.keys():
                if right in matrix:
                    used.append(right)
                    abuses.update(matrix[right])

            if abuses:
                rows.append((o, target, sorted(used), sorted(abuses)))

    if not rows:
        print("No DACL abuse opportunities found")
        print()
        return

    for o, target, used, abuses in rows[:120]:
        print(f"{color1_object(o)} -> {color1_object(target)}")
        print(f"    rights: {', '.join([color_right_name(u) for u in used])}")
        print(f"    abuses: {', '.join([_color_tag(a, Fore.YELLOW) for a in abuses])}")
    print()


def print_adcs(args, db: Database):
    print()
    print("ADCS abuse graph (ESC baseline)")
    print()

    if not db.adcs_templates and not db.adcs_cas:
        print("No ADCS objects found in collected data")
        print()
        return

    if db.adcs_cas:
        print("Enterprise CAs")
        for ca in sorted(db.adcs_cas.values(), key=lambda x: x["name"].upper()):
            web = "web-enrollment" if ca["web_enrollment"] else "rpc-only"
            enc = (
                "encryption-required"
                if ca["enforce_encryption_icertrequest"]
                else "encryption-not-required"
            )
            print(f"  - {ca['name']} ({web}, {enc})")
        print()

    if not db.adcs_findings:
        print("No exploitable ESC1-ESC4 findings derived from template ACLs")
        print()
        return

    for f in db.adcs_findings:
        kind = _color_tag(f["type"], Fore.YELLOW)
        print(
            f"- {f['principal']} can trigger {kind} via {f['template']} ({color_right_name(f['right'])})"
        )
    print()


def print_rodc(args, db: Database):
    print()
    print("RODC assessment")
    print()

    if not db.rodc_findings:
        print("No RODC policy findings in collected data")
        print()
        return

    for f in db.rodc_findings:
        print(f"- {f['domain']}: {f['kind']}")
        for e in f["entries"][:25]:
            print(f"    {e}")
    print()


def print_acls(args, db: Database):
    print()
    print("ACL/DACL Permissions (who can do what to whom)")
    print()

    entries = []
    for o in db.iter_users():
        if args.select and not o.name.upper().startswith(args.select.upper()):
            continue

        if not o.rights_by_sid:
            continue

        entries.append(o)

    if not entries:
        print("No ACL permissions found")
        print()
        return

    for o in entries:
        owned = o.name.upper() in db.owned_db
        print(color1_object(o, underline=owned))

        rights_by_sev = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
        }

        for target_sid, rights in o.rights_by_sid.items():
            if target_sid == "many":
                target_name = _color_tag("many", Fore.BLACK)
            elif target_sid not in db.objects_by_sid:
                target_name = _color_tag(f"UNKNOWN_{target_sid}", Fore.BLACK)
            else:
                target_name = color1_object(db.objects_by_sid[target_sid])

            for right in rights.keys():
                sev = RIGHT_SEVERITY.get(right, "low")
                arg = rights[right]
                if arg is not None:
                    entry = f"{color_right_name(right)}({arg}) → {target_name}"
                else:
                    entry = f"{color_right_name(right)} → {target_name}"
                rights_by_sev[sev].append(entry)

        for sev in ["critical", "high", "medium", "low"]:
            if rights_by_sev[sev]:
                for entry in rights_by_sev[sev]:
                    print(f"    {entry}")

        print()

    print()


def print_ace_inheritance(args, db: Database):
    print()
    print("ACE Inheritance Analysis")
    print()

    explicit_aces = []
    inherited_aces = []

    for o in db.objects_by_sid.values():
        if not hasattr(o, "aces_metadata"):
            continue

        for ace in o.aces_metadata:
            if ace["IsInherited"]:
                inherited_aces.append((o, ace))
            else:
                explicit_aces.append((o, ace))

    suspicious_explicit = []
    for target, ace in explicit_aces:
        principal_sid = ace.get("PrincipalSID")
        if principal_sid not in db.objects_by_sid:
            continue

        principal = db.objects_by_sid[principal_sid]
        right = ace.get("RightName")

        if right in ["GenericAll", "WriteDacl", "WriteOwner", "Owns"]:
            if principal.type == c.T_USER and not principal.is_admin:
                suspicious_explicit.append((principal, target, ace))
            elif principal.type == c.T_COMPUTER:
                suspicious_explicit.append((principal, target, ace))

    if suspicious_explicit:
        print(_color_tag("Suspicious Explicit ACE Grants", Fore.RED))
        print()
        for principal, target, ace in suspicious_explicit[:50]:
            right = ace.get("RightName")
            principal_type = ace.get("PrincipalType", "Unknown")
            print(
                f"{color1_object(principal)} → {color1_object(target)} ({color_right_name(right)}, explicit, {principal_type})"
            )
            if principal.type == c.T_COMPUTER:
                print(f"    ⚠️  Computer with explicit ACE (unusual)")
            elif target.type == c.T_DOMAIN:
                print(f"    ⚠️  Explicit grant on domain object")
            elif target.is_admin or target.can_admin:
                print(f"    ⚠️  Explicit grant on admin/path-to-admin object")
        print()
    else:
        print("No suspicious explicit ACE grants found")
        print()

    if args.select:
        print(_color_tag(f"Inherited ACEs (first 10)", Fore.CYAN))
        print()
        for target, ace in inherited_aces[:10]:
            principal_sid = ace.get("PrincipalSID")
            if principal_sid not in db.objects_by_sid:
                continue
            principal = db.objects_by_sid[principal_sid]
            right = ace.get("RightName")
            print(
                f"{color1_object(principal)} → {color1_object(target)} ({color_right_name(right)}, inherited)"
            )
        print()


def print_rbcd_matrix(args, db: Database):
    print()
    print("Resource-Based Constrained Delegation Matrix")
    print()

    rbcd_targets = []
    rbcd_sources = []

    for o in db.objects_by_sid.values():
        if not hasattr(o, "bloodhound_json"):
            continue

        allowed_to_act = o.bloodhound_json.get("AllowedToAct", [])
        if allowed_to_act:
            for delegator in allowed_to_act:
                delegator_sid = delegator.get("ObjectIdentifier")
                if delegator_sid in db.objects_by_sid:
                    delegator_obj = db.objects_by_sid[delegator_sid]
                    rbcd_targets.append((o, delegator_obj))

        allowed_to_delegate = o.bloodhound_json.get("AllowedToDelegate", [])
        if allowed_to_delegate:
            for target in allowed_to_delegate:
                target_sid = target.get("ObjectIdentifier")
                if target_sid in db.objects_by_sid:
                    target_obj = db.objects_by_sid[target_sid]
                    rbcd_sources.append((o, target_obj))

    if rbcd_targets:
        print(
            _color_tag("Computers Allowing Delegation FROM Others (RBCD)", Fore.YELLOW)
        )
        print()
        for target, delegator in rbcd_targets:
            print(
                f"{color1_object(target)} ← allows delegation from: {color1_object(delegator)}"
            )
            if not delegator.is_admin and delegator.type == c.T_USER:
                print(f"    ⚠️  Non-admin user can delegate (exploitable!)")
            elif delegator.type == c.T_COMPUTER and not delegator.is_admin:
                print(f"    ⚠️  Non-admin computer can delegate")
        print()
    else:
        print("No RBCD configurations found")
        print()

    if rbcd_sources:
        print(_color_tag("Computers with Constrained Delegation", Fore.CYAN))
        print()
        for source, target in rbcd_sources:
            print(f"{color1_object(source)} → can delegate to: {color1_object(target)}")
        print()


def print_delegation_chains(args, db: Database):
    print()
    print("Delegation Chain Analysis")
    print()

    chains = []

    for o in db.objects_by_sid.values():
        if o.type not in [c.T_USER, c.T_COMPUTER]:
            continue

        if not o.rights_by_sid:
            continue

        path = []
        current = o

        for target_sid, rights in current.rights_by_sid.items():
            if target_sid not in db.objects_by_sid:
                continue

            target = db.objects_by_sid[target_sid]

            if "AllowedToDelegate" in rights or "AllowedToAct" in rights:
                path.append((current, target, "delegation"))

                if target.unconstraineddelegation and target.is_admin:
                    path.append((target, None, "unconstrained-to-DA"))
                    chains.append(path)
                    break

                if target.is_admin:
                    chains.append(path)
                    break

    if chains:
        print(_color_tag(f"Delegation Chains to Admin ({len(chains)})", Fore.RED))
        print()
        for i, chain in enumerate(chains[:20], 1):
            print(f"{i}. ", end="")
            for j, (source, target, chain_type) in enumerate(chain):
                if j > 0:
                    print(" → ", end="")
                print(f"{color1_object(source)}", end="")
                if target:
                    print(f" ({chain_type})", end="")
            print()
            if chain[-1][2] == "unconstrained-to-DA":
                print(f"    ⚠️  Ends at unconstrained delegation (high risk)")
            print()
    else:
        print("No delegation chains to admin found")
        print()


def print_principal_types(args, db: Database):
    print()
    print("ACE Analysis by Principal Type")
    print()

    computer_aces = []
    user_aces = []
    group_aces = []

    for o in db.objects_by_sid.values():
        if not hasattr(o, "aces_metadata"):
            continue

        for ace in o.aces_metadata:
            principal_sid = ace.get("PrincipalSID")
            if principal_sid not in db.objects_by_sid:
                continue

            principal = db.objects_by_sid[principal_sid]
            right = ace.get("RightName")

            if right in ["GenericAll", "WriteDacl", "WriteOwner", "Owns"]:
                if principal.type == c.T_COMPUTER:
                    computer_aces.append((principal, o, ace))
                elif principal.type == c.T_USER:
                    user_aces.append((principal, o, ace))
                elif principal.type == c.T_GROUP:
                    group_aces.append((principal, o, ace))

    if computer_aces:
        print(_color_tag("Computers with ACL Rights (Unusual)", Fore.RED))
        print()
        for principal, target, ace in computer_aces[:30]:
            right = ace.get("RightName")
            print(
                f"{color1_object(principal)} → {color1_object(target)} ({color_right_name(right)})"
            )
            print(
                f"    ⚠️  Computers rarely need ACL rights - possible misconfiguration"
            )
        print()
    else:
        print("No computer principals with dangerous ACL rights")
        print()

    if user_aces and args.select:
        print(_color_tag("Users with ACL Rights (Normal)", Fore.CYAN))
        print()
        for principal, target, ace in user_aces[:20]:
            right = ace.get("RightName")
            print(
                f"{color1_object(principal)} → {color1_object(target)} ({color_right_name(right)})"
            )
        print()


def print_protected_analysis(args, db: Database):
    print()
    print("ACL Protection Status Analysis")
    print()

    protected_objects = []
    unprotected_hvt = []

    for o in db.objects_by_sid.values():
        if not hasattr(o, "bloodhound_json"):
            continue

        is_protected = o.bloodhound_json.get("IsACLProtected", False)

        if is_protected:
            protected_objects.append(o)
        elif o.is_admin or o.type == c.T_DOMAIN:
            unprotected_hvt.append(o)

    if protected_objects:
        print(_color_tag(f"Protected Objects ({len(protected_objects)})", Fore.GREEN))
        print()
        for o in protected_objects[:20]:
            print(f"✓ {color1_object(o)} (ACL inheritance disabled)")
        print()
    else:
        print("No ACL-protected objects found")
        print()

    if unprotected_hvt:
        print(
            _color_tag(
                f"Unprotected High-Value Objects ({len(unprotected_hvt)})", Fore.RED
            )
        )
        print()
        for o in unprotected_hvt[:20]:
            print(f"⚠️  {color1_object(o)} (vulnerable to OU-level inheritance)")
        print()
    else:
        print("All high-value objects are ACL-protected")
        print()
