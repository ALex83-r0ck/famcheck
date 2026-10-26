"""Reads the signing certificate of an APK without external tools.

Supports APK Signature Scheme v2/v3 (signing block before the ZIP central directory) and the
old v1 scheme (PKCS#7 file in META-INF). The certificate fingerprints are what stalkerware lists
like Echap/MVT publish, so renamed stalkerware is still recognised by its signature.
"""

import hashlib
import struct
import zipfile
from pathlib import Path

APK_SIG_MAGIC = b"APK Sig Block 42"
MAX_SIG_FILE = 1024 * 1024
SCHEME_IDS = (0x1B93AD61, 0xF05368C0, 0x7109871A)  # v3.1, v3, v2 (preferred order)


class ApkError(ValueError):
    pass


def _lp(buf: bytes, pos: int) -> tuple[bytes, int]:
    """uint32-length-prefixed slice."""
    if pos + 4 > len(buf):
        raise ApkError("truncated")
    (n,) = struct.unpack_from("<I", buf, pos)
    end = pos + 4 + n
    if end > len(buf):
        raise ApkError("truncated")
    return buf[pos + 4:end], end


def _signing_block_cert(data: bytes) -> bytes | None:
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if eocd < 0:
        raise ApkError("kein ZIP-Ende gefunden")
    (cd_offset,) = struct.unpack_from("<I", data, eocd + 16)
    if cd_offset < 32 or data[cd_offset - 16:cd_offset] != APK_SIG_MAGIC:
        return None
    (size,) = struct.unpack_from("<Q", data, cd_offset - 24)
    start = cd_offset - size - 8
    if start < 0:
        raise ApkError("ungültiger Signaturblock")
    pairs, pos, end = {}, start + 8, cd_offset - 24
    while pos + 12 <= end:
        (length,) = struct.unpack_from("<Q", data, pos)
        (pair_id,) = struct.unpack_from("<I", data, pos + 8)
        pairs[pair_id] = data[pos + 12:pos + 8 + length]
        pos += 8 + length
    for scheme in SCHEME_IDS:
        if scheme in pairs:
            signers, _ = _lp(pairs[scheme], 0)
            signer, _ = _lp(signers, 0)
            signed_data, _ = _lp(signer, 0)
            _digests, pos = _lp(signed_data, 0)
            certs, _ = _lp(signed_data, pos)
            cert, _ = _lp(certs, 0)
            return cert
    return None


def _der(buf: bytes, pos: int) -> tuple[int, int, int]:
    """Returns (tag, content_start, content_end) of the DER element at pos."""
    tag, length = buf[pos], buf[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    return tag, pos, pos + length


def _children(buf: bytes, start: int, end: int):
    while start < end:
        tag, cs, ce = _der(buf, start)
        yield tag, start, cs, ce
        start = ce


def _pkcs7_cert(der: bytes) -> bytes | None:
    """First certificate from a PKCS#7 SignedData (ContentInfo -> [0] -> SignedData -> [0] certificates)."""
    _, cs, ce = _der(der, 0)
    content = [c for c in _children(der, cs, ce) if c[0] == 0xA0]
    if not content:
        return None
    _, _, ics, ice = content[0]
    _, sd_s, sd_e = _der(der, ics)  # SignedData SEQUENCE
    for tag, _, cs2, ce2 in _children(der, sd_s, sd_e):
        if tag == 0xA0:  # certificates [0] IMPLICIT SET OF Certificate
            for _, cert_start, _, cert_end in _children(der, cs2, ce2):
                return der[cert_start:cert_end]
    return None


def signing_cert(path: Path) -> bytes | None:
    data = Path(path).read_bytes()
    cert = _signing_block_cert(data)
    if cert:
        return cert
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            upper = name.upper()
            if upper.startswith("META-INF/") and upper.endswith((".RSA", ".DSA", ".EC")):
                if zf.getinfo(name).file_size > MAX_SIG_FILE:  # a real one is a few KB; refuse zip bombs
                    raise ApkError("Signaturdatei unplausibel groß")
                return _pkcs7_cert(zf.read(name))
    return None


def fingerprints(path: Path) -> dict:
    """{'sha256': file hash, 'cert_sha1': ..., 'cert_sha256': ..., 'error': optional}"""
    result = {"sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
              "cert_sha1": None, "cert_sha256": None}
    try:
        cert = signing_cert(path)
        if cert:
            result["cert_sha1"] = hashlib.sha1(cert).hexdigest()
            result["cert_sha256"] = hashlib.sha256(cert).hexdigest()
    except (ApkError, zipfile.BadZipFile, IndexError, struct.error) as e:
        result["error"] = f"Signatur nicht lesbar: {e}"
    return result
