"""
Módulo de reconhecimento de infraestrutura IP para a pipeline de Bug Bounty.

O que aprendemos no tupai.pt (2026-05-01):
- Subdomínios apontam para IPs em ASNs diferentes — cada ASN tem superfície própria
- dig MX/NS/TXT revela servidores de e-mail, infraestrutura de terceiros e SPF/DMARC
- Reverse DNS (PTR) expõe hostnames internos e shared hosting
- Scan de /24 encontra painéis admin em portas não-padrão (ex.: WebsitePanel :43207)
- NTLM probe em HTTPS revela domínio AD interno sem autenticar
- Resolvers DNS abertos permitem amplificação DDoS e enumeração interna
- SMTP EHLO/banner vaza hostname real do servidor
- Correlacionar IP → subdomínio via PTR + cert SAN expande escopo
"""

import os
import re
import time
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from core.logger import Logger
from core.executor import CommandExecutor
from config.settings import DEFAULT_THREADS, DEFAULT_TIMEOUT


class IPRecon:
    """
    Reconhecimento de infraestrutura a partir dos IPs resolvidos pelos subdomínios.

    Etapas:
        1. _resolve_ips()          — Resolve A/AAAA para todos os subdomínios ativos
        2. _reverse_dns()          — PTR lookup em cada IP único
        3. _asn_lookup()           — Identifica ASN/organização de cada IP
        4. _dns_records()          — MX, NS, TXT, SOA, DMARC, SPF do domínio alvo
        5. _check_open_resolvers() — Testa se IPs respondem como resolvers DNS abertos
        6. _port_scan()            — Nmap nos IPs únicos (portas comuns + não-padrão)
        7. _service_banner()       — Pega banner de SMTP/FTP/IMAP/POP3
        8. _ntlm_probe()           — Detecta domínio AD via NTLM em HTTPS
        9. _cert_san()             — Extrai SANs do TLS para expandir escopo
    """

    INTERESTING_PORTS = [
        21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
        2083, 2087, 2096,           # cPanel
        3306, 5432,                  # databases
        6379,                        # Redis
        8080, 8443, 8888,
        10000,                       # Webmin
        43207,                       # WebsitePanel (found in tupai.pt)
    ]

    def __init__(self, logger: Optional[Logger] = None,
                 threads: int = DEFAULT_THREADS,
                 timeout: int = DEFAULT_TIMEOUT):
        self.logger = logger or Logger("ip_recon")
        self.executor = CommandExecutor(self.logger)
        self.threads = threads
        self.timeout = timeout

    # ──────────────────────────────────────────────────────────────────
    # Entry point
    # ──────────────────────────────────────────────────────────────────

    def run(self, domain: str, subdomains: List[str], output_dir: str) -> Dict:
        self.logger.banner("Reconhecimento de Infraestrutura IP")
        self.logger.info(f"Domínio alvo: {domain}")

        ip_dir = os.path.join(output_dir, "ip_recon")
        os.makedirs(ip_dir, exist_ok=True)

        # 1. Resolve IPs
        ip_map = self._resolve_ips(subdomains, ip_dir)
        unique_ips = sorted(set(ip for ips in ip_map.values() for ip in ips))
        self.logger.info(f"IPs únicos encontrados: {len(unique_ips)}")

        # 2. PTR / reverse DNS
        ptr_map = self._reverse_dns(unique_ips, ip_dir)

        # 3. ASN lookup
        asn_map = self._asn_lookup(unique_ips, ip_dir)

        # 4. DNS records do domínio raiz
        dns_records = self._dns_records(domain, ip_dir)

        # 5. Open resolver check
        open_resolvers = self._check_open_resolvers(unique_ips, ip_dir)

        # 6. Port scan
        port_results = self._port_scan(unique_ips, ip_dir)

        # 7. Service banners (SMTP, FTP, IMAP, POP3)
        banners = self._service_banners(unique_ips, port_results, ip_dir)

        # 8. NTLM probe (Exchange/IIS — leaks AD domain)
        ntlm_results = self._ntlm_probe(subdomains, ip_dir)

        # 9. TLS cert SANs
        san_results = self._cert_san(subdomains, ip_dir)

        results = {
            "success": True,
            "unique_ips": unique_ips,
            "ip_to_subdomains": ip_map,
            "ptr_map": ptr_map,
            "asn_map": asn_map,
            "dns_records": dns_records,
            "open_resolvers": open_resolvers,
            "port_results": port_results,
            "banners": banners,
            "ntlm_results": ntlm_results,
            "san_results": san_results,
        }

        self._write_summary(results, ip_dir)
        self.logger.success(f"IP recon concluído. Resultados em: {ip_dir}")
        return results

    # ──────────────────────────────────────────────────────────────────
    # 1. Resolve IPs
    # ──────────────────────────────────────────────────────────────────

    def _resolve_ips(self, subdomains: List[str], output_dir: str) -> Dict[str, List[str]]:
        """Resolve A e AAAA para cada subdomínio."""
        self.logger.step("Resolvendo IPs dos subdomínios")
        ip_map: Dict[str, List[str]] = {}

        def resolve_one(sub: str) -> Tuple[str, List[str]]:
            ips = []
            for qtype in ("A", "AAAA"):
                r = self.executor.execute(
                    f"dig +short {qtype} {sub}",
                    timeout=10, shell=True
                )
                if r["success"]:
                    for line in r["stdout"].splitlines():
                        line = line.strip()
                        if line and not line.startswith(";") and "." in line or ":" in line:
                            ips.append(line)
            return sub, ips

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(resolve_one, s): s for s in subdomains}
            for fut in as_completed(futures):
                sub, ips = fut.result()
                if ips:
                    ip_map[sub] = ips

        out_file = os.path.join(output_dir, "ip_map.txt")
        with open(out_file, "w") as f:
            for sub, ips in sorted(ip_map.items()):
                f.write(f"{sub}: {', '.join(ips)}\n")

        return ip_map

    # ──────────────────────────────────────────────────────────────────
    # 2. Reverse DNS
    # ──────────────────────────────────────────────────────────────────

    def _reverse_dns(self, ips: List[str], output_dir: str) -> Dict[str, str]:
        """PTR lookup — expõe hostnames internos e shared hosting."""
        self.logger.step("Reverse DNS (PTR)")
        ptr_map: Dict[str, str] = {}

        for ip in ips:
            r = self.executor.execute(f"dig +short -x {ip}", timeout=10, shell=True)
            if r["success"] and r["stdout"].strip():
                ptr = r["stdout"].strip().rstrip(".")
                ptr_map[ip] = ptr
                self.logger.info(f"PTR {ip} → {ptr}")
            time.sleep(0.3)

        out_file = os.path.join(output_dir, "ptr_map.txt")
        with open(out_file, "w") as f:
            for ip, ptr in sorted(ptr_map.items()):
                f.write(f"{ip}\t{ptr}\n")

        return ptr_map

    # ──────────────────────────────────────────────────────────────────
    # 3. ASN lookup
    # ──────────────────────────────────────────────────────────────────

    def _asn_lookup(self, ips: List[str], output_dir: str) -> Dict[str, str]:
        """Identifica ASN e organização de cada IP via whois ou Team Cymru."""
        self.logger.step("ASN Lookup")
        asn_map: Dict[str, str] = {}

        for ip in ips:
            # Team Cymru DNS-based ASN lookup (fast, no rate limit)
            octets = ip.split(".")
            if len(octets) == 4:
                rev = ".".join(reversed(octets))
                r = self.executor.execute(
                    f"dig +short TXT {rev}.origin.asn.cymru.com",
                    timeout=10, shell=True
                )
                if r["success"] and r["stdout"].strip():
                    asn_map[ip] = r["stdout"].strip().strip('"')
                    self.logger.info(f"ASN {ip}: {asn_map[ip]}")
            time.sleep(0.3)

        out_file = os.path.join(output_dir, "asn_map.txt")
        with open(out_file, "w") as f:
            for ip, asn in sorted(asn_map.items()):
                f.write(f"{ip}\t{asn}\n")

        return asn_map

    # ──────────────────────────────────────────────────────────────────
    # 4. DNS records (MX, NS, TXT, SPF, DMARC)
    # ──────────────────────────────────────────────────────────────────

    def _dns_records(self, domain: str, output_dir: str) -> Dict:
        """
        Coleta MX, NS, TXT, SOA, DMARC.
        Analisa SPF (~all vs -all) e DMARC (p=none vs p=reject).
        Aprendido no tupai.pt: DMARC p=none + SPF ~all = email spoofing.
        """
        self.logger.step("Coletando registros DNS (MX, NS, TXT, DMARC, SPF)")
        records: Dict = {}
        findings: List[str] = []

        for qtype in ("A", "MX", "NS", "TXT", "SOA"):
            r = self.executor.execute(
                f"dig +short {qtype} {domain}", timeout=10, shell=True
            )
            if r["success"]:
                records[qtype] = r["stdout"].strip().splitlines()

        # DMARC
        r = self.executor.execute(
            f"dig +short TXT _dmarc.{domain}", timeout=10, shell=True
        )
        if r["success"] and r["stdout"].strip():
            dmarc = r["stdout"].strip()
            records["DMARC"] = dmarc
            if "p=none" in dmarc:
                findings.append(f"DMARC p=none em {domain} — sem enforcement, email spoofing possível")
                self.logger.warning(f"DMARC p=none: {dmarc}")
            elif "p=quarantine" in dmarc:
                self.logger.info(f"DMARC p=quarantine (parcial): {dmarc}")

        # SPF
        for txt in records.get("TXT", []):
            if "v=spf1" in txt:
                records["SPF"] = txt
                if "~all" in txt:
                    findings.append(f"SPF ~all (soft fail) em {domain} — emails falsos passam na entrega")
                    self.logger.warning(f"SPF ~all: {txt}")
                elif "-all" in txt:
                    self.logger.success(f"SPF -all (hard fail): {txt}")
                break

        records["findings"] = findings

        out_file = os.path.join(output_dir, "dns_records.txt")
        with open(out_file, "w") as f:
            for k, v in records.items():
                f.write(f"=== {k} ===\n")
                if isinstance(v, list):
                    f.write("\n".join(v) + "\n")
                else:
                    f.write(str(v) + "\n")
                f.write("\n")

        return records

    # ──────────────────────────────────────────────────────────────────
    # 5. Open resolver check
    # ──────────────────────────────────────────────────────────────────

    def _check_open_resolvers(self, ips: List[str], output_dir: str) -> List[str]:
        """
        Testa se IPs respondem a queries DNS arbitrárias (amplificação DDoS).
        Aprendido no tupai.pt: 148.69.169.82/84/85 eram open resolvers 2.4x amp.
        """
        self.logger.step("Verificando open DNS resolvers")
        open_resolvers: List[str] = []

        for ip in ips:
            r = self.executor.execute(
                f"dig @{ip} google.com A +time=3 +tries=1",
                timeout=8, shell=True
            )
            if r["success"] and "ANSWER SECTION" in r["stdout"]:
                open_resolvers.append(ip)
                self.logger.warning(f"Open DNS resolver: {ip}")
            time.sleep(0.5)

        out_file = os.path.join(output_dir, "open_resolvers.txt")
        with open(out_file, "w") as f:
            f.write("\n".join(open_resolvers) + "\n")

        return open_resolvers

    # ──────────────────────────────────────────────────────────────────
    # 6. Port scan
    # ──────────────────────────────────────────────────────────────────

    def _port_scan(self, ips: List[str], output_dir: str) -> Dict[str, List[int]]:
        """
        Nmap nos IPs únicos com portas de interesse (inclui não-padrão).
        Aprendido no tupai.pt: WebsitePanel em :43207 não seria descoberto
        por um scan só das top-1000.
        """
        self.logger.step("Port scan nos IPs únicos")
        port_results: Dict[str, List[int]] = {}

        if not ips:
            return port_results

        ports_str = ",".join(str(p) for p in self.INTERESTING_PORTS)
        ips_str = " ".join(ips)
        out_file = os.path.join(output_dir, "port_scan.txt")

        r = self.executor.execute(
            f"nmap -sV -Pn -T4 -p {ports_str} {ips_str} -oN {out_file}",
            timeout=self.timeout, shell=True
        )

        if r["success"] or os.path.exists(out_file):
            # Parse nmap output
            current_ip = None
            with open(out_file) as f:
                for line in f:
                    ip_match = re.search(r"Nmap scan report for (\S+)", line)
                    if ip_match:
                        current_ip = ip_match.group(1)
                        port_results[current_ip] = []
                    port_match = re.match(r"(\d+)/tcp\s+open", line)
                    if port_match and current_ip:
                        port_results[current_ip].append(int(port_match.group(1)))

        for ip, ports in port_results.items():
            if ports:
                self.logger.info(f"{ip} open: {ports}")

        return port_results

    # ──────────────────────────────────────────────────────────────────
    # 7. Service banners
    # ──────────────────────────────────────────────────────────────────

    def _service_banners(self, ips: List[str], port_results: Dict,
                         output_dir: str) -> Dict:
        """
        Captura banners de SMTP/FTP/IMAP/POP3.
        Aprendido no tupai.pt: banner SMTP vaza hostname interno (restolho.processar.com).
        """
        self.logger.step("Capturando banners de serviços")
        banners: Dict = {}

        banner_ports = {
            21: "FTP",
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            587: "SMTP-SUBMISSION",
        }

        for ip, open_ports in port_results.items():
            for port, service in banner_ports.items():
                if port not in open_ports:
                    continue
                r = self.executor.execute(
                    f"echo QUIT | nc -w3 {ip} {port} 2>/dev/null | head -3",
                    timeout=8, shell=True
                )
                if r["success"] and r["stdout"].strip():
                    banner = r["stdout"].strip()
                    key = f"{ip}:{port}"
                    banners[key] = {"service": service, "banner": banner}
                    self.logger.info(f"Banner {key} ({service}): {banner[:80]}")
                time.sleep(0.5)

        out_file = os.path.join(output_dir, "banners.txt")
        with open(out_file, "w") as f:
            for endpoint, data in banners.items():
                f.write(f"{endpoint} [{data['service']}]:\n{data['banner']}\n\n")

        return banners

    # ──────────────────────────────────────────────────────────────────
    # 8. NTLM probe
    # ──────────────────────────────────────────────────────────────────

    def _ntlm_probe(self, subdomains: List[str], output_dir: str) -> List[Dict]:
        """
        Envia NTLM Type 1 negociation em HTTPS para extrair domínio AD interno.
        Aprendido no tupai.pt: Exchange OWA em remote.processar.com vazou
        processarlda.local e PROSRV sem autenticar.
        Funciona em: Exchange OWA, Outlook Web, IIS + Windows Auth, ADFS.
        """
        self.logger.step("NTLM probe (detecção de domínio AD)")
        results: List[Dict] = []

        # NTLM Type 1 message (base64)
        ntlm_type1 = "TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="

        for sub in subdomains:
            for path in ["/owa/", "/autodiscover/autodiscover.xml", "/", "/ecp/"]:
                url = f"https://{sub}{path}"
                r = self.executor.execute(
                    f'curl -sk -D - --max-time 8 '
                    f'-H "Authorization: NTLM {ntlm_type1}" '
                    f'"{url}" -o /dev/null 2>/dev/null | grep -i "WWW-Authenticate"',
                    timeout=12, shell=True
                )
                if r["success"] and "NTLM" in r["stdout"]:
                    # Decode NTLM Type 2 to get domain
                    ntlm_b64 = re.search(r"NTLM\s+([A-Za-z0-9+/=]+)", r["stdout"])
                    ad_domain = self._decode_ntlm_type2(ntlm_b64.group(1)) if ntlm_b64 else "unknown"
                    entry = {"url": url, "ad_domain": ad_domain, "raw": r["stdout"][:200]}
                    results.append(entry)
                    self.logger.warning(f"NTLM leak: {url} → AD domain: {ad_domain}")
                time.sleep(1)

        out_file = os.path.join(output_dir, "ntlm_probe.txt")
        with open(out_file, "w") as f:
            for r in results:
                f.write(f"URL: {r['url']}\nAD Domain: {r['ad_domain']}\n\n")

        return results

    def _decode_ntlm_type2(self, b64: str) -> str:
        """Extrai NetBIOS domain name de um NTLM Type 2 challenge."""
        try:
            import base64
            data = base64.b64decode(b64 + "==")
            # Target name offset at byte 12-13 (little-endian)
            if len(data) < 56:
                return "unknown"
            name_len = int.from_bytes(data[12:14], "little")
            name_off = int.from_bytes(data[20:24], "little")
            name_bytes = data[name_off:name_off + name_len]
            return name_bytes.decode("utf-16-le", errors="ignore").strip("\x00")
        except Exception:
            return "unknown"

    # ──────────────────────────────────────────────────────────────────
    # 9. TLS cert SANs
    # ──────────────────────────────────────────────────────────────────

    def _cert_san(self, subdomains: List[str], output_dir: str) -> Dict[str, List[str]]:
        """
        Extrai Subject Alternative Names do certificado TLS para expandir escopo.
        SANs frequentemente revelam subdomínios internos ou aplicações ocultas.
        """
        self.logger.step("Extraindo SANs de certificados TLS")
        san_map: Dict[str, List[str]] = {}

        for sub in subdomains[:20]:  # limite para evitar demora
            r = self.executor.execute(
                f"echo | openssl s_client -connect {sub}:443 -servername {sub} 2>/dev/null "
                f"| openssl x509 -noout -text 2>/dev/null | grep -A1 'Subject Alternative Name'",
                timeout=10, shell=True
            )
            if r["success"] and "DNS:" in r["stdout"]:
                sans = re.findall(r"DNS:([^\s,]+)", r["stdout"])
                if sans:
                    san_map[sub] = sans
                    self.logger.info(f"SANs de {sub}: {sans}")
            time.sleep(0.5)

        out_file = os.path.join(output_dir, "cert_sans.txt")
        with open(out_file, "w") as f:
            for sub, sans in san_map.items():
                f.write(f"{sub}:\n  " + "\n  ".join(sans) + "\n\n")

        return san_map

    # ──────────────────────────────────────────────────────────────────
    # Summary
    # ──────────────────────────────────────────────────────────────────

    def _write_summary(self, results: Dict, output_dir: str):
        findings = []

        if results["open_resolvers"]:
            findings.append(f"[HIGH] Open DNS resolvers: {results['open_resolvers']}")

        for ip, ports in results["port_results"].items():
            for p in ports:
                if p in (43207, 10000, 2083, 2087):
                    findings.append(f"[HIGH] Porta admin não-padrão {p} aberta em {ip}")

        for sub, slist in results["san_results"].items():
            new_subs = [s for s in slist if s not in results["ip_to_subdomains"]]
            if new_subs:
                findings.append(f"[INFO] Novos subdomínios via SAN em {sub}: {new_subs}")

        for entry in results["ntlm_results"]:
            findings.append(f"[HIGH] NTLM leak AD domain '{entry['ad_domain']}' em {entry['url']}")

        for r in results.get("dns_records", {}).get("findings", []):
            findings.append(f"[MEDIUM] {r}")

        out_file = os.path.join(output_dir, "ip_recon_findings.txt")
        with open(out_file, "w") as f:
            f.write(f"=== IP Recon Findings ({len(findings)}) ===\n\n")
            for finding in findings:
                f.write(finding + "\n")

        if findings:
            self.logger.warning(f"{len(findings)} achados de infraestrutura:")
            for f_item in findings:
                self.logger.warning(f"  {f_item}")
