#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse
import subprocess
from pathlib import Path
from datetime import datetime

# ---------------- child: roda um único EFI ----------------
def run_single_efi(efi_path: Path, rootfs: Path) -> int:
    """
    Executa um único EFI via Qiling API (UEFI).
    Retorna exit code (0 ok, !=0 fail).
    """
    try:
        from qiling import Qiling
        from qiling.const import QL_OS

        ostype = getattr(QL_OS, "UEFI", None)
        if ostype is None:
            print("[child] ERRO: QL_OS.UEFI não existe nessa versão do Qiling.")
            return 4

        ql = Qiling([str(efi_path)], rootfs=str(rootfs), ostype=ostype)
        ql.run()
        return 0

    except Exception as e:
        print(f"[child] EXCEPTION: {e}")
        return 3


# ---------------- parent: roda todos com timeout ----------------
def main_parent(mod_dir: Path, timeout_sec: int, out_dir: Path, modulo: str) -> int:
    mod_dir = mod_dir.resolve()
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = out_dir / f"qiling_run_{ts}.log"

    def log_print(fh, msg=""):
        print(msg)
        fh.write(msg + "\n")
        fh.flush()

    # lista todos .efi
    all_efi_files = sorted([p for p in mod_dir.iterdir()
                            if p.is_file() and p.name.lower().endswith(".efi")])

    # -------- filtro por módulo (novo) --------
    if modulo and modulo.upper() != "ALL":
        wanted = modulo.strip()

        # permite passar sem extensão
        if not wanted.lower().endswith(".efi"):
            wanted += ".efi"

        wanted_lower = wanted.lower()

        efi_files = [p for p in all_efi_files if p.name.lower() == wanted_lower]

        # se não achou exato, tenta contains (mais tolerante)
        if not efi_files:
            efi_files = [p for p in all_efi_files if wanted_lower in p.name.lower()]

    else:
        efi_files = all_efi_files

    with open(log_path, "w", encoding="utf-8") as log:
        log_print(log, f"[*] diretorio_de_modulos: {mod_dir}")
        log_print(log, f"[*] timeout por modulo (s): {timeout_sec}")
        log_print(log, f"[*] modulo solicitado: {modulo}")
        log_print(log, f"[*] log salvo em: {log_path}")
        log_print(log, f"[*] total de .efi no diretorio: {len(all_efi_files)}")
        log_print(log, f"[*] total de .efi para executar: {len(efi_files)}")

        if modulo and modulo.upper() != "ALL" and not efi_files:
            log_print(log, f"[!] Modulo '{modulo}' nao encontrado em {mod_dir}")
            return 5

        if not efi_files:
            log_print(log, "[*] Nenhum .efi encontrado. Encerrando.")
            return 0

        ok = 0
        fail = 0
        tout = 0

        for efi in efi_files:
            log_print(log, "\n" + "=" * 80)
            log_print(log, f"[*] Rodando: {efi.name}")
            log_print(log, "=" * 80)

            # chama a si mesmo em modo single usando o MESMO python
            cmd = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--single",
                str(efi),
                str(mod_dir)  # rootfs simples = pasta dos módulos
            ]

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                out, _ = proc.communicate(timeout=timeout_sec)

                if out:
                    for line in out.splitlines():
                        log_print(log, line)

                if proc.returncode == 0:
                    ok += 1
                    log_print(log, f"[+] OK: {efi.name}")
                else:
                    fail += 1
                    log_print(log, f"[-] FAIL({proc.returncode}): {efi.name}")

            except subprocess.TimeoutExpired:
                tout += 1
                proc.kill()
                try:
                    out, _ = proc.communicate(timeout=2)
                    if out:
                        for line in out.splitlines():
                            log_print(log, line)
                except Exception:
                    pass

                log_print(log, f"[!] TIMEOUT ({timeout_sec}s): {efi.name}")

        log_print(log, "\n" + "=" * 80)
        log_print(log, f"[*] Finalizado. OK={ok} FAIL={fail} TIMEOUT={tout}")
        log_print(log, "=" * 80)

    print(f"[*] Log final em: {log_path}")
    return 0


# ---------------- entrypoint ----------------
def main():
    ap = argparse.ArgumentParser(
        description="Roda Qiling (UEFI) em todos .efi de um diretório, com timeout por módulo."
    )

    # modo interno
    ap.add_argument("--single", action="store_true",
                    help=argparse.SUPPRESS)
    ap.add_argument("args", nargs="*")

    # modo normal (3 params + modulo)
    ap.add_argument("--diretorio_de_modulos", type=str, help="Pasta com .efi")
    ap.add_argument("--timeout", type=int, help="Timeout em segundos por módulo")
    ap.add_argument("--diretorio_saida", type=str, help="Pasta de saída do log")
    ap.add_argument("--modulo", type=str, default="ALL",
                    help="Nome do modulo para executar (ex: CpuDxe.efi) ou ALL")

    ns = ap.parse_args()

    # -------- single mode --------
    if ns.single:
        if len(ns.args) < 2:
            print("[child] Uso interno errado: --single <efi> <rootfs>")
            return 2
        efi = Path(ns.args[0]).resolve()
        rootfs = Path(ns.args[1]).resolve()
        return run_single_efi(efi, rootfs)

    # -------- normal mode --------
    if not (ns.diretorio_de_modulos and ns.timeout is not None and ns.diretorio_saida):
        print("Uso:")
        print("  py -3.13 run_qiling_dir.py "
              "--diretorio_de_modulos <pasta_efi> "
              "--timeout <segundos> "
              "--diretorio_saida <pasta_log> "
              "[--modulo ALL|NomeModulo.efi]")
        return 1

    mod_dir = Path(ns.diretorio_de_modulos)
    out_dir = Path(ns.diretorio_saida)

    if not mod_dir.exists() or not mod_dir.is_dir():
        print(f"[!] diretorio_de_modulos inválido: {mod_dir}")
        return 3

    return main_parent(mod_dir, int(ns.timeout), out_dir, ns.modulo)


if __name__ == "__main__":
    sys.exit(main())
