"""Reproduce a verified release from the Japanese ROM, without old build folders.

This applies shipped IPS patches; it does not compile edited translations.
Only the Python standard library is required.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def apply_ips(source, patch):
    if not patch.startswith(b'PATCH'):
        raise ValueError('IPS header is invalid')
    output = bytearray(source)
    cursor = 5
    while True:
        if cursor + 3 > len(patch):
            raise ValueError('IPS record is truncated')
        marker = patch[cursor:cursor + 3]
        cursor += 3
        if marker == b'EOF':
            break
        address = int.from_bytes(marker, 'big')
        if cursor + 2 > len(patch):
            raise ValueError('IPS size is truncated')
        length = int.from_bytes(patch[cursor:cursor + 2], 'big')
        cursor += 2
        if length:
            data = patch[cursor:cursor + length]
            if len(data) != length:
                raise ValueError('IPS data is truncated')
            cursor += length
        else:
            if cursor + 3 > len(patch):
                raise ValueError('IPS run is truncated')
            length = int.from_bytes(patch[cursor:cursor + 2], 'big')
            data = patch[cursor + 2:cursor + 3] * length
            cursor += 3
        end = address + length
        if end > 0x400000:
            raise ValueError('Patch exceeds the supported 4 MiB ROM')
        if end > len(output):
            output.extend(bytes(end - len(output)))
        output[address:end] = data
    tail = patch[cursor:]
    if len(tail) == 3:
        size = int.from_bytes(tail, 'big')
        if size > 0x400000:
            raise ValueError('IPS output size exceeds 4 MiB')
        output = output[:size] + bytes(max(0, size - len(output)))
    elif tail:
        raise ValueError('Unexpected IPS trailing data')
    return bytes(output)


def safe_file(root, name):
    # Release paths are flat; never interpret a catalog entry as an arbitrary path.
    if Path(name).name != name or '/' in name or '\\' in name or ':' in name:
        raise ValueError('Invalid release filename')
    return root / name


def reproduce(rom_path, bundle, output, variant='all'):
    catalog = json.loads((bundle / 'release_catalog.json').read_text(encoding='utf8'))
    original = rom_path.read_bytes()
    if sha(original) != catalog['source_sha256']:
        raise ValueError('일본판 원본 ROM이 아닙니다. 파일을 변경하지 않았습니다.')
    planned = {}
    for label, release in catalog['variants'].items():
        if variant not in ('all', label):
            continue
        patch = safe_file(bundle, release['patch']).read_bytes()
        if sha(patch) != release['patch_sha256']:
            raise ValueError('패치 파일이 손상되었습니다: ' + label)
        rom = apply_ips(original, patch)
        checksum = sum(w[0] for w in struct.iter_unpack('>H', rom[0x200:])) & 65535
        if sha(rom) != release['rom_sha256'] or int.from_bytes(rom[0x18e:0x190], 'big') != checksum:
            raise ValueError('완성 ROM 검사 실패: ' + label)
        folder = output / label
        planned[folder / release['rom']] = rom
        for name, expected in release['assets'].items():
            data = safe_file(bundle, name).read_bytes()
            if sha(data) != expected:
                raise ValueError('부속 파일이 손상되었습니다: ' + name)
            planned[folder / name] = data
    if not planned:
        raise ValueError('선택한 판이 없습니다.')
    for path, data in planned.items():
        if path.resolve() == rom_path.resolve():
            raise ValueError('원본 ROM을 출력 파일로 사용할 수 없습니다.')
        if path.exists() and path.read_bytes() != data:
            raise ValueError('기존 파일을 덮어쓰지 않습니다: ' + str(path))
    # Validate every input and destination before creating any output.
    for path, data in planned.items():
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
            temporary = Path(tmp.name)
            tmp.write(data)
        try:
            # Exclusive destination creation also protects against a concurrent writer.
            with path.open('xb') as target:
                target.write(temporary.read_bytes())
        finally:
            temporary.unlink(missing_ok=True)
    if rom_path.read_bytes() != original:
        raise ValueError('원본 ROM이 실행 도중 변경되었습니다.')
    return {str(path): sha(data) for path, data in planned.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rom', type=Path)
    parser.add_argument('--bundle', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--variant', choices=['all', 'normal', 'music'], default='all')
    args = parser.parse_args()
    try:
        result = reproduce(args.rom, args.bundle, args.output or args.bundle / 'output', args.variant)
    except (OSError, ValueError, KeyError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print('최신 패치 재현 완료. 원본 ROM은 보존했습니다.')
    for path in result:
        if path.endswith('.md'):
            print(path)
    return 0


if __name__ == '__main__':
    sys.exit(main())
