rom __future__ import annotations
import argparse
import hashlib
import os
import random
import sys
from typing import List, Tuple
from PIL import Image
import codecs

MAGIC = b"STEG1"           # 5 bytes magic/version
HEADER_LEN = 5 + 2 + 4 + 4  # MAGIC (5) + passcheck(2) + payload_len(4) + checksum(4) = 15 bytes

# ------------------------- Helpers -------------------------

def rot13_bytes(data: bytes) -> bytes:
    """Apply ROT13 to a UTF-8 text payload (bytes <-> str safely)."""
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        # If not valid UTF-8, just return unchanged
        return data
    return codecs.encode(s, "rot_13").encode("utf-8")


def pass_seed(passcode: str) -> int:
    """Derive a deterministic PRNG seed from passcode (SHA-256 -> int)."""
    return int.from_bytes(hashlib.sha256(passcode.encode("utf-8")).digest(), "big")


def pass_check(passcode: str) -> bytes:
    """Short verifier (first 2 bytes of SHA-256)."""
    return hashlib.sha256(passcode.encode("utf-8")).digest()[:2]


def checksum4(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()[:4]


def u32_be(x: int) -> bytes:
    return x.to_bytes(4, "big")


def u32_from_be(b: bytes) -> int:
    return int.from_bytes(b, "big")


def bytes_to_bits(data: bytes) -> List[int]:
    bits: List[int] = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: List[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("Bit stream length must be a multiple of 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | (b & 1)
        out.append(byte)
    return bytes(out)

# ----------------------- Image I/O -------------------------

def image_to_channels(img: Image.Image) -> Tuple[List[int], Tuple[int, int]]:
    """Flatten RGB pixels into a list of channels [R,G,B,R,G,B,...]."""
    if img.mode != "RGB":
        img = img.convert("RGB")
    w, h = img.size
    pixels = list(img.getdata())  # List[Tuple[int,int,int]]
    channels: List[int] = []
    for r, g, b in pixels:
        channels.extend((r, g, b))
    return channels, (w, h)


def channels_to_image(channels: List[int], size: Tuple[int, int]) -> Image.Image:
    w, h = size
    if len(channels) != w * h * 3:
        raise ValueError("Channel length mismatch for the image size")
    pixels: List[Tuple[int, int, int]] = []
    for i in range(0, len(channels), 3):
        pixels.append((channels[i], channels[i+1], channels[i+2]))
    out = Image.new("RGB", (w, h))
    out.putdata(pixels)
    return out

# -------------------- Core Steganography -------------------

def plan_positions(n_channels: int, n_bits: int, seed: int) -> List[int]:
    """Return the first n_bits channel indices to write/read, in a PRNG-shuffled order."""
    if n_bits > n_channels:
        raise ValueError("Not enough capacity to store data in the image")
    idx = list(range(n_channels))
    rnd = random.Random(seed)
    rnd.shuffle(idx)
    return idx[:n_bits]


def embed_bits_into_channels(channels: List[int], bits: List[int], positions: List[int]) -> None:
    for bit, pos in zip(bits, positions):
        channels[pos] = (channels[pos] & ~1) | (bit & 1)


def extract_bits_from_channels(channels: List[int], positions: List[int]) -> List[int]:
    return [channels[pos] & 1 for pos in positions]

# ---------------------- Public API -------------------------

def embed(input_path: str, output_path: str, message: str, passcode: str) -> None:
    img = Image.open(input_path)
    channels, size = image_to_channels(img)

    # Prepare payload: ROT13-encoded text in UTF-8
    payload = rot13_bytes(message.encode("utf-8"))

    header = MAGIC + pass_check(passcode) + u32_be(len(payload)) + checksum4(payload)
    blob = header + payload
    bits = bytes_to_bits(blob)

    positions = plan_positions(len(channels), len(bits), pass_seed(passcode))

    embed_bits_into_channels(channels, bits, positions)
    out = channels_to_image(channels, size)

    # Always save as PNG to preserve data
    ext = os.path.splitext(output_path)[1].lower()
    if ext != ".png":
        print("[i] For safety, saving as PNG (lossless) regardless of extension.")
        output_path = output_path + ".png" if not ext else output_path.replace(ext, ".png")

    out.save(output_path, format="PNG")
    print(f"[+] Embedded {len(payload)} bytes (ROT13) into {output_path}")


def extract(input_path: str, passcode: str) -> str:
    img = Image.open(input_path)
    channels, _ = image_to_channels(img)

    # First, read header bits (fixed length)
    header_bits_len = HEADER_LEN * 8
    positions_header = plan_positions(len(channels), header_bits_len, pass_seed(passcode))
    header_bits = extract_bits_from_channels(channels, positions_header)
    header = bits_to_bytes(header_bits)

    if len(header) != HEADER_LEN or header[:5] != MAGIC:
        raise ValueError("Invalid or corrupted stego header (magic mismatch)")

    if header[5:7] != pass_check(passcode):
        raise PermissionError("Passcode check failed. Wrong passcode or corrupted data.")

    payload_len = u32_from_be(header[7:11])
    expected_ck = header[11:15]

    # Now read payload bits (immediately following header positions in the same PRNG order)
    total_bits = (HEADER_LEN + payload_len) * 8
    positions_all = plan_positions(len(channels), total_bits, pass_seed(passcode))
    payload_positions = positions_all[header_bits_len:]

    payload_bits = extract_bits_from_channels(channels, payload_positions)
    payload = bits_to_bytes(payload_bits)

    if checksum4(payload) != expected_ck:
        raise ValueError("Payload checksum mismatch. Data may be corrupted.")

    # Decode ROT13 back to plaintext
    try:
        rot_back = rot13_bytes(payload)  # ROT13 is involutive
        plaintext = rot_back.decode("utf-8")
    except Exception:
        plaintext = rot_back.decode("utf-8", errors="replace")

    return plaintext

# ------------------------- CLI -----------------------------

def main():
    parser = argparse.ArgumentParser(description="Image Steganography Tool (Jan 2025)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_embed = sub.add_parser("embed", help="Embed a message into an image")
    p_embed.add_argument("-i", "--input", required=True, help="Input image (PNG/BMP recommended)")
    p_embed.add_argument("-o", "--output", required=True, help="Output image path (PNG will be used)")
    p_embed.add_argument("-m", "--message", required=True, help="Message to hide (plaintext)")
    p_embed.add_argument("-p", "--passcode", required=True, help="Passcode for access")

    p_extract = sub.add_parser("extract", help="Extract a hidden message from an image")
    p_extract.add_argument("-i", "--input", required=True, help="Stego image path")
    p_extract.add_argument("-p", "--passcode", required=True, help="Passcode used when embedding")

    args = parser.parse_args()

    try:
        if args.cmd == "embed":
            embed(args.input, args.output, args.message, args.passcode)
        elif args.cmd == "extract":
            msg = extract(args.input, args.passcode)
            print("[+] Extracted message:")
            print(msg)
        else:
            parser.error("Unknown command")
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
