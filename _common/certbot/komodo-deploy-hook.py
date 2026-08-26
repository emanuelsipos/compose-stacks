#!/usr/bin/env python3

import json
import os
import stat
import sys
from pathlib import Path
from urllib import error, parse, request


class HookFailure(Exception):
    pass


class RejectRedirects(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    try:
        lineage_value = os.environ["RENEWED_LINEAGE"]
        consumer_gid_value = os.environ["CERT_CONSUMER_GID"]
        webhook_url = os.environ["KOMODO_WEBHOOK_URL"]
        secret_file = os.environ["KOMODO_WEBHOOK_SECRET_FILE"]

        if not consumer_gid_value.isascii() or not consumer_gid_value.isdigit():
            raise HookFailure("invalid consumer group")
        consumer_gid = int(consumer_gid_value)

        parsed_url = parse.urlsplit(webhook_url)
        if (
            parsed_url.scheme != "https"
            or not parsed_url.netloc
            or parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_url.fragment
        ):
            raise HookFailure("invalid webhook configuration")

        live_root = Path("/etc/letsencrypt/live").resolve(strict=True)
        archive_root = Path("/etc/letsencrypt/archive").resolve(strict=True)
        lineage = Path(lineage_value).resolve(strict=True)
        fullchain = (lineage / "fullchain.pem").resolve(strict=True)
        privkey = (lineage / "privkey.pem").resolve(strict=True)
        archive_lineage = privkey.parent

        if (
            lineage.parent != live_root
            or archive_lineage.parent != archive_root
            or fullchain.parent != archive_lineage
            or not fullchain.is_file()
            or not privkey.is_file()
        ):
            raise HookFailure("invalid certificate paths")

        owner_uid = os.geteuid()
        owner_gid = os.getegid()
        directories = (live_root, archive_root, lineage, archive_lineage)
        for directory in directories:
            details = directory.stat()
            if details.st_uid != owner_uid or details.st_mode & 0o022:
                raise HookFailure("certificate storage is not owner-controlled")

        for old_key in archive_lineage.glob("privkey*.pem"):
            details = old_key.lstat()
            if (
                not stat.S_ISREG(details.st_mode)
                or stat.S_ISLNK(details.st_mode)
                or details.st_uid != owner_uid
                or details.st_mode & 0o022
            ):
                raise HookFailure("invalid certificate paths")
            os.chown(old_key, owner_uid, owner_gid)
            os.chmod(old_key, 0o600)

        for directory in directories:
            os.chown(directory, owner_uid, consumer_gid)
            os.chmod(directory, 0o710)
        os.chown(fullchain, owner_uid, consumer_gid)
        os.chmod(fullchain, 0o644)
        os.chown(privkey, owner_uid, consumer_gid)
        os.chmod(privkey, 0o640)

        secret_path = Path(secret_file)
        secret_details = secret_path.lstat()
        if (
            not stat.S_ISREG(secret_details.st_mode)
            or stat.S_ISLNK(secret_details.st_mode)
            or secret_details.st_mode & 0o077
        ):
            raise HookFailure("invalid webhook secret")

        descriptor = os.open(secret_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            secret = os.read(descriptor, 8193).rstrip(b"\r\n")
        finally:
            os.close(descriptor)
        if not secret or len(secret) > 8192 or b"\r" in secret or b"\n" in secret:
            raise HookFailure("invalid webhook secret")

        payload = json.dumps(
            {"ref": "refs/heads/main"}, separators=(",", ":")
        ).encode()
        webhook_request = request.Request(
            webhook_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Gitlab-Token": secret.decode("ascii"),
            },
            method="POST",
        )
        opener = request.build_opener(RejectRedirects())
        with opener.open(webhook_request, timeout=15) as response:
            if not 200 <= response.status < 300:
                raise HookFailure("webhook delivery failed")
    except KeyError:
        print("komodo-deploy-hook: missing configuration", file=sys.stderr)
        return 1
    except UnicodeDecodeError:
        print("komodo-deploy-hook: invalid webhook secret", file=sys.stderr)
        return 1
    except HookFailure as exc:
        print(f"komodo-deploy-hook: {exc}", file=sys.stderr)
        return 1
    except (OSError, RuntimeError, ValueError, error.HTTPError, error.URLError):
        print("komodo-deploy-hook: operation failed", file=sys.stderr)
        return 1

    print("komodo-deploy-hook: reload requested")
    return 0


if __name__ == "__main__":
    sys.exit(main())
