from contextlib import closing
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from threading import Thread
import unittest

from des import E, FP, IP, P, PC1, PC2, S_BOXES, SHIFTS, trace_block
from des_demo import DemoHandler, EXAMPLE_KEY, STAGES, build_trace, explain_step, format_result, parse_block, parse_key
from des_reference import describe_table


class DESDemoTextTests(unittest.TestCase):
    def test_text_round_trip(self):
        for plaintext in ("HelloDES", "Hi", " caf\u00e9 ", "\U0001f642" * 2, " "):
            with self.subTest(plaintext=plaintext):
                block = parse_block(plaintext, decrypt=False)
                key = parse_key(EXAMPLE_KEY)
                encrypted = trace_block(block, key).output
                ciphertext = format_result(encrypted, decrypt=False)
                self.assertEqual(parse_block(ciphertext, decrypt=True), encrypted)
                self.assertEqual(len(ciphertext), 12)
                decrypted = trace_block(encrypted, key, decrypt=True).output
                self.assertEqual(format_result(decrypted, decrypt=True), plaintext)

    def test_short_text_to_block(self):
        self.assertEqual(parse_block("Hi", decrypt=False), 0x4869000000000000)

    def test_rejects_invalid_plaintext(self):
        for text in ("", "123456789", "\u00e9" * 5, "Hi\0", "Hi\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_block(text, decrypt=False)

    def test_rejects_invalid_base64_or_block_size(self):
        for text in ("not base64!", "SGk=", "", "\u00e9"):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "Base64"):
                parse_block(text, decrypt=True)

    def test_rejects_non_text_decryption_output(self):
        for block in (0xFF00000000000000, 0, 0x6100620000000000):
            with self.subTest(block=block), self.assertRaises(ValueError):
                format_result(block, decrypt=True)

    def test_key_uses_utf8_bytes_without_modification(self):
        self.assertEqual(parse_key("KeyDemo!"), 0x4B657944656D6F21)
        self.assertEqual(parse_key(" \u00e9\u00e9\u00e9 "), 0x20C3A9C3A9C3A920)

    def test_rejects_invalid_text_keys(self):
        for text in ("", "short", "123456789", "\u00e9" * 5):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "tepat 8 byte UTF-8"):
                parse_key(text)
        for text in ("1234567\0", "1234567\n"):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "satu baris"):
                parse_key(text)

    def test_walkthrough_uses_values_from_trace(self):
        key = 0x133457799BBCDFF1
        enc = trace_block(0x0123456789ABCDEF, key)
        ciphertext = format_result(enc.output, decrypt=False)
        start = explain_step(enc, 0, ciphertext)
        self.assertIn("IP", start[1][0])
        self.assertIn("L00", start[2][0])
        self.assertIn("F0CCAAF556678F", start[3][1])
        round_one = explain_step(enc, 1, ciphertext)
        self.assertEqual(len(round_one), 6)
        self.assertIn("1B02EFFC7072", round_one[0][1])
        self.assertIn("Untuk S1, baca 011000", round_one[3][1])
        self.assertIn("(00) memilih baris 0", round_one[3][1])
        self.assertIn("(1100) memilih kolom 12 (C dalam heksadesimal)", round_one[3][1])
        self.assertIn("0101 dalam biner", round_one[3][1])
        self.assertIn("EF4A6544", round_one[-1][1])
        self.assertIn(ciphertext, explain_step(enc, len(STAGES) - 1, ciphertext)[2][1])

        dec = trace_block(enc.output, key, decrypt=True)
        self.assertIn("K16 hingga K01", explain_step(dec, 0, "")[3][1])
        self.assertIn("K16", explain_step(dec, 1, "")[0][0])


class DESReferenceTests(unittest.TestCase):
    def test_permutation_grids_match_des_tables(self):
        for name, positions in (("IP", IP), ("FP", FP), ("E", E), ("P", P), ("PC-1", PC1), ("PC-2", PC2)):
            with self.subTest(name=name):
                intro, grid, _ = describe_table(name, None, 0)
                shown = tuple(int(cell) for line in grid.splitlines()[1:] for cell in line.split("|")[1].split())
                self.assertEqual(shown, positions)
                self.assertIn(f"bit keluaran ke-1 berasal dari bit masukan ke-{positions[0]}", intro)

    def test_permutation_examples_match_trace_bits(self):
        key = 0x133457799BBCDFF1
        trace = trace_block(0x0123456789ABCDEF, key)
        r = trace.rounds[0]
        examples = (("IP", 0, trace.after_ip, 64), ("FP", 17, trace.output, 64),
                    ("PC-1", 0, trace.key_after_pc1, 56), ("PC-2", 1, r.subkey, 48),
                    ("E", 1, r.expanded, 48), ("P", 1, r.permuted, 32))
        for name, step, result, size in examples:
            with self.subTest(name=name):
                _, _, example = describe_table(name, trace, step, key=key)
                bits = "".join(example.split("Nilai bit: ")[1].split())
                self.assertEqual(bits, f"{result:0{size}b}"[:len(bits)])
                self.assertIn(f"Keluaran (heks): {result:0{size // 4}X}", example)

    def test_sboxes_and_rotation_schedule_match_trace(self):
        key = 0x133457799BBCDFF1
        ciphertext = trace_block(0x0123456789ABCDEF, key).output
        trace = trace_block(ciphertext, key, decrypt=True)
        _, shifts, rotation = describe_table("Shifts", trace, 1)
        shown = tuple(int(cell) for line in shifts.splitlines()[1::2] for cell in line.split(":")[1].split())
        self.assertEqual(shown, SHIFTS)
        self.assertIn("Untuk K16, rotasi 1 bit", rotation)
        for i, table in enumerate(S_BOXES):
            with self.subTest(sbox=i + 1):
                _, grid, example = describe_table(f"S{i + 1}", trace, 1)
                shown = tuple(tuple(int(cell, 16) for cell in line.split("|")[1].split())
                              for line in grid.splitlines()[1:])
                self.assertEqual(shown, table)
                output = f"{trace.rounds[0].substituted:032b}"[4 * i:4 * (i + 1)]
                self.assertIn(f"= {output} biner", example)


class DESOperationTests(unittest.TestCase):
    def test_animation_values_match_each_operation(self):
        key = parse_key(EXAMPLE_KEY)
        block = parse_block("Hi", decrypt=False)
        encrypted = build_trace(block, key, decrypt=False, source="Hi")
        ciphertext = encrypted["output"]
        decrypted = build_trace(parse_block(ciphertext, decrypt=True), key, decrypt=True, source=ciphertext)

        for result in (encrypted, decrypted):
            first, key_schedule, *rounds, last = result["groups"]
            self.assertEqual([group["stage"] for group in rounds], list(range(1, 17)))
            self.assertEqual(len(key_schedule["operations"]), 35)
            subkeys = [op["outputs"][0]["label"] for op in key_schedule["operations"] if op.get("table") == "PC-2"]
            self.assertEqual(subkeys, [f"K{k:02}" for k in range(1, 17)])
            for group in rounds:
                self.assertEqual([op["kind"] for op in group["operations"]],
                                 ["mapping", "xor", "sboxes", "mapping", "xor", "mapping"])
            for group in (first, key_schedule, *rounds, last):
                for op in group["operations"]:
                    with self.subTest(group=group["title"], operation=op["title"]):
                        inputs = [item.get("binary", "") for item in op["inputs"]]
                        output = "".join(item.get("binary", "") for item in op["outputs"])
                        if op["kind"] == "mapping":
                            source = "".join(inputs)
                            self.assertEqual("".join(source[i - 1] if i else "0" for i in op["positions"]), output)
                        elif op["kind"] == "xor":
                            self.assertEqual("".join(str(int(a != b)) for a, b in zip(*inputs, strict=True)), output)
                        elif op["kind"] == "sboxes":
                            self.assertEqual("".join(row["input"] for row in op["lookups"]), inputs[0])
                            self.assertEqual("".join(row["output"] for row in op["lookups"]), output)
                            for box, row in zip(S_BOXES, op["lookups"], strict=True):
                                self.assertEqual(box[row["row"]][int(row["column"], 16)], int(row["output"], 2))

        self.assertEqual(encrypted["groups"][0]["operations"][1]["positions"], (*range(1, 17), *(0,) * 48))
        self.assertEqual(decrypted["groups"][0]["operations"][0]["inputs"][0]["text"], ciphertext)
        self.assertEqual(decrypted["groups"][-1]["operations"][-1]["outputs"][0]["text"], "Hi")
        self.assertEqual([group["operations"][1]["inputs"][1]["label"] for group in decrypted["groups"][2:-1]],
                         [f"K{k:02}" for k in range(16, 0, -1)])


class DESWebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class TestHandler(DemoHandler):
            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), TestHandler)
        cls.port = server.server_port
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        cls.addClassCleanup(server.server_close)
        cls.addClassCleanup(thread.join)
        cls.addClassCleanup(server.shutdown)

    def request(self, method, path, body=None, content_type="application/json"):
        with closing(HTTPConnection("127.0.0.1", self.port, timeout=5)) as conn:
            conn.request(method, path, body=body, headers={"Content-Type": content_type})
            response = conn.getresponse()
            return response.status, response.getheader("Content-Type"), response.read()

    def post(self, block, key, mode):
        status, _, body = self.request("POST", "/api/trace", json.dumps({"block": block, "key": key, "mode": mode}))
        return status, json.loads(body)

    def test_serves_page_and_assets(self):
        for path, content_type in (("/", "text/html"), ("/style.css", "text/css"), ("/app.js", "text/javascript")):
            with self.subTest(path=path):
                actual, mime, body = self.request("GET", path)
                self.assertEqual(actual, 200)
                self.assertTrue(mime.startswith(content_type))
                self.assertTrue(body)
                if path == "/":
                    self.assertIn(b'<html lang="id">', body)
        self.assertEqual(self.request("GET", "/des.py")[0], 404)

    def test_example_and_roundtrip(self):
        status, _, body = self.request("GET", "/api/example")
        self.assertEqual(status, 200)
        example = json.loads(body)
        self.assertEqual([stage["label"] for stage in example["steps"]], list(STAGES))
        self.assertEqual(sum(len(group["operations"]) for group in example["groups"]), 137)
        self.assertIn("Keluaran (heks)", example["steps"][0]["examples"]["IP"])
        self.assertEqual(example["steps"][0]["title"], "Permutasi awal")
        self.assertIn("58 50 42", example["tables"]["IP"]["grid"])

        plaintext, key = " caf\u00e9 ", " \u00e9\u00e9\u00e9 "
        status, encrypted = self.post(plaintext, key, "encrypt")
        self.assertEqual(status, 200)
        self.assertEqual(encrypted["steps"][0]["values"][0]["hex"], "20636166C3A92000")
        self.assertEqual(len(encrypted["steps"][0]["values"][0]["binary"]), 64)
        status, decrypted = self.post(encrypted["output"], key, "decrypt")
        self.assertEqual(status, 200)
        self.assertEqual(decrypted["output"], plaintext)
        self.assertIn("K16", decrypted["steps"][1]["flow"][2][0])

    def test_validation_and_non_text_output(self):
        status, response = self.post("long input", EXAMPLE_KEY, "encrypt")
        self.assertEqual((status, response["field"]), (400, "block"))
        status, response = self.post("Hello", "short", "encrypt")
        self.assertEqual((status, response["field"]), (400, "key"))
        self.assertIn("Kunci harus tepat 8 byte UTF-8", response["error"])
        self.assertEqual(self.request("POST", "/api/trace", "x" * 4097)[0], 413)
        self.assertEqual(self.request("POST", "/api/trace", "not JSON")[0], 400)
        self.assertEqual(self.request("POST", "/api/trace", "123", "text/plain")[0], 415)
        bad_block = trace_block(0xFF00000000000000, parse_key(EXAMPLE_KEY)).output
        status, response = self.post(format_result(bad_block, decrypt=False), EXAMPLE_KEY, "decrypt")
        self.assertEqual((status, response["output"]), (200, ""))
        self.assertEqual(response["steps"][-1]["values"][-1]["hex"], "FF00000000000000")
