"""DES reference tables and worked examples from the trace."""

from des import DESTrace, E, FP, IP, P, PC1, PC2, S_BOXES, SHIFTS, sbox_lookup

PERMUTATIONS = {
    "IP": ("Permutasi awal", IP, 64, 8, "Susun ulang bit masukan sebelum membagi blok menjadi L00 dan R00."),
    "FP": ("Permutasi akhir", FP, 64, 8, "Susun ulang gabungan R16 dan L16. FP adalah kebalikan dari IP."),
    "E": ("Ekspansi bagian kanan", E, 32, 6, "Tiap baris memilih enam bit dari bagian kanan sebelum XOR dengan kunci putaran."),
    "P": ("Permutasi putaran", P, 32, 8, "Susun ulang 32 bit keluaran S-box untuk mendapatkan f(R, K)."),
    "PC-1": ("Pemilihan bit kunci 1", PC1, 64, 7, "Buang bit 8, 16, ..., 64 (bit paritas), lalu susun ulang sisanya."),
    "PC-2": ("Pemilihan bit kunci 2", PC2, 56, 6, "Pilih dan susun ulang bit dari bagian C dan D yang sudah dirotasi."),
}
TABLE_TITLES = {
    **{name: info[0] for name, info in PERMUTATIONS.items()},
    "Shifts": "Jadwal rotasi kunci",
    **{f"S{i}": "Kotak substitusi" for i in range(1, len(S_BOXES) + 1)},
}


def describe_table(
    name: str, trace: DESTrace | None, step: int, *, key: int | None = None
) -> tuple[str, str, str]:
    """Return instructions, the full table, and a worked example from the trace."""
    r = trace.rounds[step - 1] if trace and 1 <= step <= len(trace.rounds) else None
    example = ("Pilih putaran 01 sampai 16 untuk melihat contohnya." if trace
               else "Klik Jalankan untuk melihat contoh perhitungan.")

    if name in PERMUTATIONS:
        _, positions, width, columns, purpose = PERMUTATIONS[name]
        intro = (f"Masukan: {width} bit. Keluaran: {len(positions)} bit. {purpose}\n\n"
                 "Baca tabel dari kiri ke kanan, baris demi baris. Tiap angka menunjukkan posisi bit masukan "
                 "yang harus disalin. Posisi 1 ada di ujung kiri blok masukan. "
                 f"Angka pertama, {positions[0]}, berarti bit keluaran ke-1 berasal dari bit masukan ke-{positions[0]}.")
        lines = ["Keluar | Posisi bit masukan"]
        for i in range(0, len(positions), columns):
            group = positions[i:i + columns]
            lines.append(f" {i + 1:2}-{i + len(group):<2} | " + " ".join(f"{pos:2}" for pos in group))

        live = None
        if trace and name == "IP":
            live = trace.block, trace.after_ip
        elif trace and name == "FP":
            live = trace.before_fp, trace.output
        elif trace and name == "PC-1" and key is not None:
            live = key, trace.key_after_pc1
        elif r and name == "E":
            live = r.right_in, r.expanded
        elif r and name == "P":
            live = r.substituted, r.permuted
        elif r and name == "PC-2":
            live = (r.key_left << 28) | r.key_right, r.subkey

        if live is not None:
            source, result = live
            first = positions[:columns]
            labels = " ".join(f"{i:2}" for i in range(1, len(first) + 1))
            inputs = " ".join(f"{pos:2}" for pos in first)
            values = " ".join(f"{(source >> (width - pos)) & 1:2}" for pos in first)
            example = (f"Masukan (heks) : {source:0{width // 4}X}\n"
                       f"Keluaran (heks): {result:0{len(positions) // 4}X}\n\n"
                       f"{len(first)} bit keluaran pertama:\n"
                       f"Keluaran : {labels}\nMasukan  : {inputs}\nNilai bit: {values}")
        return intro, "\n".join(lines), example

    if name == "Shifts":
        intro = ("Geser bagian C dan D ke kiri sesuai jumlah bit pada tabel sebelum membuat tiap kunci putaran. "
                 "Pindahkan bit yang keluar di kiri ke ujung kanan. Saat dekripsi, gunakan kunci putaran dalam urutan terbalik.")
        lines = []
        for start in (0, 8):
            lines.append("Kunci  : " + " ".join(f"{n:2}" for n in range(start + 1, start + 9)))
            lines.append("Rotasi : " + " ".join(f"{n:2}" for n in SHIFTS[start:start + 8]))
        if r:
            k = r.key_index
            shift = SHIFTS[k - 1]
            example = (f"Untuk K{k:02}, rotasi {shift} bit ke kiri.\n"
                       f"C{k:02} = {r.key_left:07X}\nD{k:02} = {r.key_right:07X}")
        return intro, "\n".join(lines), example

    index = int(name[1:]) - 1
    intro = (f"Gunakan {name} untuk kelompok 6 bit ke-{index + 1} dari hasil XOR. "
             "Gabungkan bit pertama dan terakhir menjadi angka biner untuk memilih baris (0 hingga 3). "
             "Gunakan empat bit tengah untuk memilih kolom. Kolom dan isi tabel memakai heksadesimal (A=10, F=15).")
    lines = ["Kol | " + " ".join(f"{col:X}" for col in range(16))]
    for row, values in enumerate(S_BOXES[index]):
        lines.append(f"  {row} | " + " ".join(f"{value:X}" for value in values))
    if r:
        chunk, row, col, result = sbox_lookup(r.mixed, index)
        example = (f"Masukan : {chunk:06b} (6 bit)\nBaris   : {row} (bit pertama dan terakhir)\n"
                   f"Kolom   : {col:X} (heks, empat bit di tengah)\nSel     : {result:X} heks = {result:04b} biner")
    return intro, "\n".join(lines), example
