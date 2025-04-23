#!/usr/bin/env python3
"""
Bug Bounty Deivao-Recon - Aplicação principal aprimorada

Este script é o ponto de entrada principal para a pipeline de Bug Bounty em Python.
Ele coordena a execução do Recon com melhorias em:
- Tratamento de erros
- Documentação
- Organização do código
- Funcionalidades adicionais
"""

import os
import sys
import argparse
from datetime import datetime
from pathlib import Path
import traceback
from typing import Dict, Optional, Union, List

# Adicionar diretório raiz ao path de forma mais robusta
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from core.logger import Logger
from core.executor import CommandExecutor
from tools.tool_checker import ToolChecker
from modules.subdomain_recon import SubdomainRecon
from reporting.report_generator import ReportGenerator
from reporting.notify import NotifyManager
from config.settings import DEFAULT_THREADS, DEFAULT_TIMEOUT, DEFAULT_LOG_LEVEL


class BugBountyRecon:
    """Classe principal que coordena a execução da recon de Bug Bounty.
    
    Atributos:
        args (Namespace): Argumentos da linha de comando
        start_time (datetime): Timestamp de início da execução
        logger (Logger): Instância do logger para registro de eventos
        output_dir (str): Diretório de saída para os resultados
        executor (CommandExecutor): Gerenciador de execução de comandos
        tool_checker (ToolChecker): Verificador de ferramentas necessárias
        notify_manager (NotifyManager): Gerenciador de notificações
        report_generator (ReportGenerator): Gerador de relatórios
    """

    def __init__(self, args: argparse.Namespace):
        """Inicializa a recon de Bug Bounty.
        
        Args:
            args: Argumentos da linha de comando parseados
        """
        self.args = args
        self.start_time = datetime.now()
        
        self._setup_logger()
        self._setup_directories()
        self._setup_components()
        
        self.logger.banner("Deivao-Recon - Python Edition")
        self._log_initial_config()
        
        if args.notify:
            self._send_start_notification()

    def _setup_logger(self):
        """Configura o sistema de logging."""
        self.logger = Logger(
            name="deivao-recon",
            log_file=self.args.log_file,
            level="DEBUG" if self.args.verbose else DEFAULT_LOG_LEVEL
        )

    def _setup_directories(self):
        """Configura os diretórios de saída."""
        self.output_dir = os.path.expanduser(f"~/Documents/Bugbounty/{self.args.domain}")
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Criar subdiretórios antecipadamente
        self.recon_dir = os.path.join(self.output_dir, "recon")
        self.reports_dir = os.path.join(self.output_dir, "reports")
        os.makedirs(self.recon_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)

    def _setup_components(self):
        """Configura os componentes principais da recon."""
        self.executor = CommandExecutor(self.logger)
        self.tool_checker = ToolChecker(self.logger)
        
        # Configuração condicional do notificador
        self.notify_manager = NotifyManager(self.logger)
        if self.args.notify_config:
            try:
                self.notify_manager.load_config(self.args.notify_config)
            except Exception as e:
                self.logger.error(f"Falha ao carregar configuração de notificação: {str(e)}")
                self.args.notify = False  # Desativa notificações se a configuração falhar
        
        self.report_generator = ReportGenerator(self.logger)

    def _log_initial_config(self):
        """Registra a configuração inicial no log."""
        config_details = [
            f"Domínio alvo: {self.args.domain}",
            f"Diretório de saída: {self.output_dir}",
            f"Threads: {self.args.threads}",
            f"Timeout: {self.args.timeout} segundos",
            f"Modo verboso: {'Ativado' if self.args.verbose else 'Desativado'}",
            f"Notificações: {'Ativadas' if self.args.notify else 'Desativadas'}"
        ]
        
        for detail in config_details:
            self.logger.info(detail)

    def _send_start_notification(self):
        """Envia notificação de início da recon."""
        if self.args.notify:
            try:
                self.notify_manager.notify(
                    message=f"Recon iniciada para o domínio: {self.args.domain}",
                    title="Bug Bounty Deivao-Recon Iniciada",
                    level="info"
                )
            except Exception as e:
                self.logger.error(f"Falha ao enviar notificação inicial: {str(e)}")

    def run(self) -> Union[Dict, bool]:
        """Executa a recon completa de Bug Bounty.
        
        Returns:
            Dict: Resultados da recon se bem-sucedido
            bool: False se ocorrer falha
        """
        try:
            if self.args.check_only:
                return self.check_tools()
            
            self.logger.banner("Reconhecimento de Subdomínios")
            
            subdomain_recon = SubdomainRecon(
                self.logger,
                threads=self.args.threads,
                timeout=self.args.timeout
            )
            
            results = subdomain_recon.run(
                domain=self.args.domain,
                output_dir=self.recon_dir
            )
            
            if results and results.get("success", False):
                results["subdomains_file"] = results.get("final_file")
                
                # Geração de relatório e notificação
                report_file = self.generate_final_report(results)
                self.print_summary(results, report_file)
                
                if self.args.notify:
                    self._send_completion_notification(results, report_file)
                
                return results
            
            self.logger.error("Falha no reconhecimento de subdomínios")
            return False
            
        except KeyboardInterrupt:
            self.logger.warning("Recon interrompida pelo usuário")
            return False
        except Exception as e:
            self.logger.error(f"Erro crítico na recon: {str(e)}")
            self.logger.debug(traceback.format_exc())
            return False

    def _send_completion_notification(self, results: Dict, report_file: str):
        """Envia notificação de conclusão da recon.
        
        Args:
            results: Resultados da precon
            report_file: Caminho para o relatório gerado
        """
        try:
            subdomains_count = len(results.get("subdomains", []))
            duration = datetime.now() - self.start_time
            
            message = (
                f"Deivao-Recon concluída para {self.args.domain}\n"
                f"Subdomínios encontrados: {subdomains_count}\n"
                f"Duração: {duration.total_seconds() / 60:.2f} minutos\n"
                f"Relatório: {report_file}"
            )
            
            self.notify_manager.notify(
                message=message,
                title="Bug Bounty Deivao-Recon Concluída",
                level="success"
            )
        except Exception as e:
            self.logger.error(f"Falha ao enviar notificação de conclusão: {str(e)}")

    def check_tools(self, silent: bool = False) -> bool:
        """Verifica se todas as ferramentas necessárias estão instaladas.
        
        Args:
            silent: Se True, suprime saída detalhada
            
        Returns:
            bool: True se todas as ferramentas estão disponíveis
        """
        if not silent:
            self.logger.banner("Verificação de Ferramentas")
        
        all_tools_status = self.tool_checker.check_all_tools()
        per_module = all(isinstance(v, dict) for v in all_tools_status.values())

        if not silent:
            self._log_tool_check_results(all_tools_status, per_module)
        
        # Verificar se há ferramentas faltantes
        if per_module:
            missing_tools = sum(len(module["missing"]) for module in all_tools_status.values())
        else:
            missing_tools = len(all_tools_status.get("missing", []))
        
        return missing_tools == 0

    def _log_tool_check_results(self, results: Dict, per_module: bool):
        """Registra os resultados da verificação de ferramentas.
        
        Args:
            results: Resultados da verificação
            per_module: Se os resultados estão organizados por módulo
        """
        if per_module:
            for module, module_tools in results.items():
                self.logger.info(f"\nMódulo: {module}")
                self._log_tool_status(module_tools)
        else:
            self.logger.info("\nResumo geral:")
            self._log_tool_status(results)

    def _log_tool_status(self, tools: Dict):
        """Registra o status das ferramentas de um módulo.
        
        Args:
            tools: Dicionário com status das ferramentas
        """
        self.logger.info(f"  Disponíveis: {', '.join(tools['available']) if tools.get('available') else 'Nenhuma'}")
        self.logger.info(f"  Faltantes: {', '.join(tools['missing']) if tools.get('missing') else 'Nenhuma'}")
        
        if tools.get('alternatives'):
            alternatives = [f"{k}->{v}" for k, v in tools['alternatives'].items()]
            self.logger.info(f"  Alternativas: {', '.join(alternatives)}")

    def generate_final_report(self, subdomain_results: Dict) -> str:
        """Gera o relatório final consolidando todos os resultados.
        
        Args:
            subdomain_results: Resultados do reconhecimento de subdomínios
            
        Returns:
            str: Caminho para o relatório final principal
        """
        self.logger.banner("Geração de Relatório Final")
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_name = f"bug_bounty_report_{self.args.domain}_{timestamp}"
        formats = [("md", "Markdown")]
        
        if self.args.html_report:
            formats.append(("html", "HTML"))
        if self.args.json_report:
            formats.append(("json", "JSON"))
        
        report_files = []
        report_data = self._prepare_report_data(subdomain_results)
        
        for format, format_name in formats:
            report_file = os.path.join(self.reports_dir, f"{base_name}.{format}")
            self.logger.info(f"Gerando relatório {format_name} em {report_file}")
            
            try:
                self.report_generator.generate_report(report_data, report_file, format=format)
                report_files.append(report_file)
                self.logger.success(f"Relatório {format_name} gerado com sucesso")
            except Exception as e:
                self.logger.error(f"Falha ao gerar relatório {format_name}: {str(e)}")
        
        return report_files[0] if report_files else ""

    def _prepare_report_data(self, results: Dict) -> Dict:
        """Prepara os dados para o relatório.
        
        Args:
            results: Resultados da recon
            
        Returns:
            Dict: Dados estruturados para o relatório
        """
        duration = datetime.now() - self.start_time
        subdomains = results.get("subdomains", [])
        active_subdomains = results.get("active_subdomains", [])
        
        return {
            "title": f"Relatório de Recon - {self.args.domain}",
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "domain": self.args.domain,
            "summary": (
                f"Este relatório apresenta os resultados da Deivao-Recon de Bug Bounty "
                f"para o domínio {self.args.domain}."
            ),
            "stats": {
                "Duração": f"{duration.total_seconds() / 60:.2f} minutos",
                "Subdomínios Encontrados": len(subdomains),
                "Subdomínios Ativos": len(active_subdomains),
                "Taxa de Sucesso": f"{len(active_subdomains)/len(subdomains)*100:.1f}%" if subdomains else "N/A",
            },
            "details": {
                "subdomains": subdomains,
                "active_subdomains": active_subdomains,
                "tools_used": results.get("tools_used", [])
            }
        }

    def print_summary(self, subdomain_results: Dict, report_file: str):
        """Imprime um resumo dos resultados da execução.
        
        Args:
            subdomain_results: Resultados do reconhecimento
            report_file: Caminho para o relatório gerado
        """
        self.logger.banner("Resumo da Deivao-Recon")
        
        duration = datetime.now() - self.start_time
        subdomains_count = len(subdomain_results.get("subdomains", []))
        active_count = len(subdomain_results.get("active_subdomains", []))
        
        summary_lines = [
            f"Duração total: {duration.total_seconds() / 60:.2f} minutos",
            f"Subdomínios encontrados: {subdomains_count}",
            f"Subdomínios ativos: {active_count}",
            f"Taxa de sucesso: {(active_count/subdomains_count)*100:.1f}%" if subdomains_count else "N/A",
            f"Relatório principal: {report_file}",
            f"Diretório completo de resultados: {self.output_dir}"
        ]
        
        for line in summary_lines:
            self.logger.info(line)


def parse_args() -> argparse.Namespace:
    """Analisa os argumentos da linha de comando.
    
    Returns:
        Namespace: Argumentos parseados
    """
    parser = argparse.ArgumentParser(
        description="Deivao-recon - Python Edition",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Argumentos obrigatórios
    parser.add_argument(
        "domain",
        help="Domínio alvo para a pipeline"
    )
    
    # Argumentos de execução
    execution_group = parser.add_argument_group("Configuração de Execução")
    execution_group.add_argument(
        "-t", "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Número de threads para execução paralela"
    )
    execution_group.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout para comandos externos em segundos"
    )
    execution_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Ativar modo verboso (logs detalhados)"
    )
    execution_group.add_argument(
        "--log-file",
        help="Arquivo para salvar os logs"
    )
    
    # Argumentos de relatório
    report_group = parser.add_argument_group("Opções de Relatório")
    report_group.add_argument(
        "--html-report",
        action="store_true",
        help="Gerar relatório em formato HTML"
    )
    report_group.add_argument(
        "--json-report",
        action="store_true",
        help="Gerar relatório em formato JSON"
    )
    
    # Argumentos de notificação
    notification_group = parser.add_argument_group("Configuração de Notificações")
    notification_group.add_argument(
        "--notify",
        action="store_true",
        help="Enviar notificações sobre o progresso"
    )
    notification_group.add_argument(
        "--notify-config",
        help="Arquivo de configuração para notificações"
    )
    
    # Modos especiais
    modes_group = parser.add_argument_group("Modos Especiais")
    modes_group.add_argument(
        "--check-only",
        action="store_true",
        help="Apenas verificar ferramentas necessárias"
    )
    
    return parser.parse_args()


def main():
    """Função principal de execução do script."""
    try:
        args = parse_args()
        recon = BugBountyRecon(args)
        
        if not recon.run():
            sys.exit(1)
            
    except Exception as e:
        print(f"Erro fatal: {str(e)}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    main()