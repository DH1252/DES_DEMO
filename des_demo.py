"""Jalankan demo DES secara lokal dengan `python3 des_demo.py`."""

import argparse
import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from des import DESTrace, MASK32, SHIFTS, sbox_lookup, trace_block
from des_reference import TABLE_TITLES, describe_table

EXAMPLE_BLOCK = "HelloDES"
EXAMPLE_KEY = "KeyDemo!"
BLOCK_BYTES = 8
STAGES = ("IP", *(f"{n:02}" for n in range(1, 17)), "FP")
WEB = Path(__file__).resolve().with_name("web")
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}


def _encode_text(text: str, label: str) -> bytes:
    if any(char in text for char in "\0\r\n"):
        raise ValueError(f"{label} harus satu baris tanpa karakter NUL.")
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{label} harus berupa teks UTF-8 yang valid.") from None


def parse_key(text: str) -> int:
    data = _encode_text(text, "Kunci")
    if len(data) != BLOCK_BYTES:
        raise ValueError(f"Kunci harus tepat 8 byte UTF-8. Anda memasukkan {len(data)} byte.")
    return int.from_bytes(data, "big")


def parse_block(text: str, *, decrypt: bool) -> int:
    if decrypt:
        message = "Masukkan teks sandi Base64 yang mewakili tepat 8 byte."
        try:
            data = base64.b64decode(text.strip(), validate=True)
        except ValueError:
            raise ValueError(message) from None
        if len(data) != BLOCK_BYTES:
            raise ValueError(message)
    else:
        data = _encode_text(text, "Teks asli")
        if not 1 <= len(data) <= BLOCK_BYTES:
            raise ValueError("Masukkan teks asli sepanjang 1 hingga 8 byte UTF-8. Satu karakter bisa memakai lebih dari satu byte.")
        data = data.ljust(BLOCK_BYTES, b"\0")
    return int.from_bytes(data, "big")


def format_result(block: int, *, decrypt: bool) -> str:
    data = block.to_bytes(BLOCK_BYTES, "big")
    if not decrypt:
        return base64.b64encode(data).decode("ascii")
    # Only trailing NULs are padding. Keep user-entered spaces as text.
    text = data.rstrip(b"\0").decode("utf-8")
    if not text or any(char in text for char in "\0\r\n"):
        raise ValueError("Hasilnya bukan teks asli satu baris.")
    return text


def explain_step(trace: DESTrace, step: int, output: str) -> tuple[tuple[str, str], ...]:
    if step == 0:
        if trace.decrypt:
            heading = "Baca teks sandi Base64"
            preparation = f"Dekode Base64 untuk mendapatkan 8 byte teks sandi: {trace.block:016X} (heksadesimal)."
        else:
            heading = "Ubah teks asli menjadi byte"
            size = len(trace.block.to_bytes(BLOCK_BYTES, "big").rstrip(b"\0"))
            missing = BLOCK_BYTES - size
            padding = f" Tambahkan {missing} byte nol di akhir." if missing else ""
            preparation = (f"Teks asli terdiri dari {size} byte UTF-8.{padding} "
                           f"Blok 8 byte dalam heksadesimal: {trace.block:016X}.")
        direction, order = ("Dekripsi", "K16 hingga K01") if trace.decrypt else ("Enkripsi", "K01 hingga K16")
        return (
            (f"1. {heading}", preparation),
            ("2. Siapkan kunci",
             "Kunci terdiri dari 8 byte UTF-8. PC-1 membuang bit terakhir setiap byte (bit paritas) "
             f"dan menyusun ulang 56 bit sisanya: {trace.key_after_pc1:014X}. Bagi hasilnya menjadi dua "
             "bagian, masing-masing 28 bit. DES merotasi kedua bagian dan memilih bit untuk membentuk 16 kunci putaran. "
             f"{direction} memakai {order}."),
            ("3. Terapkan permutasi awal (IP)",
             "Salin bit masukan sesuai urutan pada tabel IP: "
             f"{trace.block:016X} -> {trace.after_ip:016X}."),
            ("4. Pisahkan bagian kiri dan kanan",
             f"32 bit pertama menjadi L00 = {trace.after_ip >> 32:08X}. "
             f"32 bit terakhir menjadi R00 = {trace.after_ip & MASK32:08X}. Keduanya menjadi masukan putaran pertama."),
        )
    if step == len(STAGES) - 1:
        last = trace.rounds[-1]
        if not trace.decrypt:
            display = (f"Teks sandi 8 byte dalam Base64: {output}. "
                       "Klik Balik proses untuk mendekripsinya dengan kunci yang sama.")
        elif output:
            display = ("Buang byte nol di akhir jika ada, lalu baca sisanya sebagai UTF-8. "
                       f"Teks aslinya adalah {output!r}.")
        else:
            display = ("Setelah byte pengisi dibuang, hasilnya tidak bisa dibaca sebagai teks UTF-8 satu baris. "
                       "Lihat byte mentah di tab Nilai.")
        return (
            ("1. Tukar posisi kedua bagian",
             f"Gabungkan R16 ({last.right_out:08X}) lalu L16 ({last.left_out:08X}) "
             f"menjadi blok 64 bit {trace.before_fp:016X}."),
            ("2. Terapkan permutasi akhir (FP)",
             f"Salin bit sesuai urutan pada tabel FP untuk mendapatkan {trace.output:016X}. "
             "FP adalah kebalikan dari IP."),
            ("3. Tampilkan hasil", display),
            ("4. Mengapa urutan kunci dibalik saat dekripsi",
             "Keluaran kiri adalah masukan kanan yang disalin. Hitung ulang f dengan masukan kanan itu dan kunci putaran "
             "yang sama. XOR hasilnya dengan keluaran kanan untuk mendapatkan masukan kiri: XOR dua kali dengan nilai "
             "yang sama mengembalikan nilai awal. Saat dekripsi, IP menempatkan R16 hasil enkripsi di kiri dan L16 di kanan. "
             "DES kemudian mengulangi langkah putaran yang sama dengan urutan kunci K16 hingga K01."),
        )

    r = trace.rounds[step - 1]
    k = r.key_index
    shift = SHIFTS[k - 1]
    first, row, col, first_output = sbox_lookup(r.mixed, 0)
    group = f"{first:06b}"
    return (
        (f"1. Tentukan kunci putaran K{k:02}",
         f"Mulai dengan L{step - 1:02} = {r.left_in:08X} dan R{step - 1:02} = {r.right_in:08X}. "
         f"Untuk membuat K{k:02}, geser C{k - 1:02} dan D{k - 1:02} masing-masing {shift} bit ke kiri. "
         f"Pindahkan bit yang keluar di kiri ke ujung kanan. Hasilnya C{k:02} = {r.key_left:07X} "
         f"dan D{k:02} = {r.key_right:07X}. Pilih 48 bit sesuai urutan pada tabel PC-2: K{k:02} = {r.subkey:012X}."),
        ("2. Perluas bagian kanan (E)",
         f"Ikuti tabel E untuk menyalin bit dari {r.right_in:08X}. Tambahkan satu bit di kiri dan satu bit di kanan "
         "tiap kelompok 4 bit. Untuk kelompok pertama dan terakhir, ambil bit tetangga dari ujung seberang. "
         f"Delapan kelompok 6 bit ini membentuk {r.expanded:012X}."),
        ("3. Lakukan XOR dengan kunci putaran",
         "XOR menghasilkan 1 jika kedua bit berbeda dan 0 jika keduanya sama. "
         f"{r.expanded:012X} XOR {r.subkey:012X} = {r.mixed:012X}."),
        ("4. Cari nilai pada tabel S-box",
         f"Bagi hasil XOR menjadi delapan kelompok 6 bit. Pakai kelompok pertama ({group}) untuk membaca tabel S1. "
         f"Gabungkan bit pertama dan terakhir ({group[0]}{group[-1]}) untuk memilih baris {row}. Empat bit tengah "
         f"({group[1:5]}) menentukan kolom {col} ({col:X} dalam heksadesimal). Nilai pada baris dan kolom itu "
         f"adalah {first_output:04b} dalam biner. Gabungkan delapan hasil 4 bit untuk mendapatkan {r.substituted:08X}."),
        ("5. Terapkan permutasi P pada keluaran S-box",
         "Susun ulang 32 bit sesuai tabel P agar bit dari satu S-box tersebar ke beberapa S-box pada putaran berikutnya. "
         f"Hasilnya f(R, K) = {r.permuted:08X}."),
        ("6. Tentukan bagian kiri dan kanan yang baru",
         f"Bagian kanan semula menjadi L{step:02} = {r.left_out:08X}. "
         f"Untuk mendapatkan R{step:02}, lakukan XOR antara bagian kiri semula dan f(R, K): "
         f"{r.left_in:08X} XOR {r.permuted:08X} = {r.right_out:08X}."),
    )


def _build_step(trace: DESTrace, step: int, output: str, key: int) -> dict:
    label = STAGES[step]
    before, after = (("teks sandi", "teks asli") if trace.decrypt else ("teks asli", "teks sandi"))
    if label == "IP":
        title = "Permutasi awal"
        note = "Susun ulang 64 bit sesuai tabel IP, lalu bagi blok menjadi L00 dan R00."
        rows = (("Blok masukan", trace.block, 64), ("Blok setelah permutasi", trace.after_ip, 64),
                ("Bagian kiri (L00)", trace.after_ip >> 32, 32),
                ("Bagian kanan (R00)", trace.after_ip & MASK32, 32))
        flow = ((f"Byte {before}", f"{trace.block:016X}"), ("Permutasi awal (IP)", f"{trace.after_ip:016X}"),
                ("L00 / Kiri", f"{trace.after_ip >> 32:08X}"), ("R00 / Kanan", f"{trace.after_ip & MASK32:08X}"))
    elif label == "FP":
        title = "Pertukaran dan permutasi akhir"
        note = "Gabungkan R16 dan L16, lalu terapkan kebalikan dari permutasi awal."
        last = trace.rounds[-1]
        rows = (("Bagian kanan (R16)", last.right_out, 32), ("Bagian kiri (L16)", last.left_out, 32),
                ("Blok setelah pertukaran", trace.before_fp, 64), ("Blok keluaran", trace.output, 64))
        flow = (("R16 / Pertama", f"{last.right_out:08X}"), ("L16 / Kedua", f"{last.left_out:08X}"),
                ("R16 diikuti L16", f"{trace.before_fp:016X}"), ("Permutasi akhir (FP)", "Kebalikan IP"),
                (f"Byte {after}", f"{trace.output:016X}"))
    else:
        r = trace.rounds[step - 1]
        title = f"Putaran Feistel {label}"
        note = "Bagian kanan menjadi bagian kiri baru. Bagian kanan baru adalah hasil XOR bagian kiri semula dengan f(R, K)."
        rows = (("Masukan kanan", r.right_in, 32), ("Ekspansi E", r.expanded, 48),
                (f"Kunci putaran K{r.key_index:02}", r.subkey, 48), ("XOR dengan kunci", r.mixed, 48),
                ("Keluaran S-box", r.substituted, 32), ("Permutasi P / f", r.permuted, 32),
                ("Bagian kanan baru", r.right_out, 32))
        flow = ((f"L{step - 1:02} / Masukan", f"{r.left_in:08X}"), (f"R{step - 1:02} / Masukan", f"{r.right_in:08X}"),
                (f"K{r.key_index:02} / Kunci", f"{r.subkey:012X}"), ("Feistel f(R, K)", f"{r.permuted:08X}"),
                (f"R{label} / Hasil XOR", f"{r.right_out:08X}"), (f"L{label} / Salinan R", f"{r.left_out:08X}"))
    return {
        "label": label, "title": title, "note": note, "flow": flow,
        "walkthrough": explain_step(trace, step, output),
        # Send strings so 64-bit values never lose precision in the browser.
        "values": [{"label": name, "bits": width, "hex": f"{number:0{width // 4}X}", "binary": f"{number:0{width}b}"}
                   for name, number, width in rows],
        "examples": {name: describe_table(name, trace, step, key=key)[2] for name in TABLE_TITLES},
    }


def _catalog() -> dict:
    tables = {}
    for name, title in TABLE_TITLES.items():
        intro, grid, _ = describe_table(name, None, 0)
        tables[name] = {"title": title, "intro": intro, "grid": grid}
    return tables


TABLES = _catalog()


def build_trace(block: int, key: int, *, decrypt: bool) -> dict:
    trace = trace_block(block, key, decrypt=decrypt)
    try:
        output = format_result(trace.output, decrypt=decrypt)
    except ValueError:
        output = ""
        status = "Hasilnya bukan teks UTF-8 satu baris. Periksa kunci dan teks sandi, atau pilih FP lalu buka tab Nilai."
    else:
        order = "K16 hingga K01" if decrypt else "K01 hingga K16"
        status = f"Urutan kunci putaran: {order}."
    return {"output": output, "status": status, "tables": TABLES,
            "steps": [_build_step(trace, step, output, key) for step in range(len(STAGES))]}


class DemoHandler(BaseHTTPRequestHandler):
    def _send(self, status: int, content_type: str, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data: dict):
        self._send(status, "application/json; charset=utf-8", json.dumps(data).encode("utf-8"))

    def do_GET(self):
        path = self.path.partition("?")[0]
        if path in ASSETS:
            name, content_type = ASSETS[path]
            self._send(200, content_type, (WEB / name).read_bytes())
        elif path == "/api/example":
            block = parse_block(EXAMPLE_BLOCK, decrypt=False)
            data = build_trace(block, parse_key(EXAMPLE_KEY), decrypt=False)
            self._json(200, {**data, "block": EXAMPLE_BLOCK, "key": EXAMPLE_KEY})
        else:
            self._json(404, {"error": "Tidak ditemukan."})

    def do_POST(self):
        if self.path.partition("?")[0] != "/api/trace":
            self._json(404, {"error": "Tidak ditemukan."})
            return
        if self.headers.get_content_type() != "application/json":
            self._json(415, {"error": "Kirim data dalam format JSON."})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = 0
        if not 0 < length <= 4096:
            self._json(413 if length > 4096 else 400, {"error": "Ukuran permintaan tidak valid."})
            return
        try:
            data = json.loads(self.rfile.read(length))
        except (ValueError, RecursionError):
            data = None
        if not isinstance(data, dict) or data.get("mode") not in ("encrypt", "decrypt"):
            self._json(400, {"error": "Pilih enkripsi atau dekripsi."})
            return
        for field, label in (("block", "Blok masukan"), ("key", "Kunci")):
            if not isinstance(data.get(field), str):
                self._json(400, {"error": f"{label} harus berupa teks.", "field": field})
                return
        decrypt = data["mode"] == "decrypt"
        try:
            block = parse_block(data["block"], decrypt=decrypt)
        except ValueError as exc:
            self._json(400, {"error": str(exc), "field": "block"})
            return
        try:
            key = parse_key(data["key"])
        except ValueError as exc:
            self._json(400, {"error": str(exc), "field": "key"})
            return
        self._json(200, build_trace(block, key, decrypt=decrypt))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="alamat server (bawaan: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="port HTTP lokal (bawaan: 8000)")
    args = parser.parse_args()
    with ThreadingHTTPServer((args.host, args.port), DemoHandler) as server:
        print(f"Visualisasi DES: http://{args.host}:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
