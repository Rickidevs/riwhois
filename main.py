#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import sys
import socket
import re
import whois
import requests
from datetime import datetime
from colorama import init, Fore, Style, Back

init(autoreset=True)

class WhoisTool:
    def __init__(self):
        self.header = f"""
{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗
{Fore.GREEN}║ {Fore.CYAN}                  DOMAIN & IP WHOIS LOOKUP TOOL             {Fore.GREEN}║
{Fore.GREEN}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        
    def banner(self):
        print(self.header)
    
    def is_ip_address(self, query):
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if re.match(ip_pattern, query):
            try:
                socket.inet_aton(query)
                return True
            except socket.error:
                return False
        return False
    
    def get_domains_from_ip(self, ip_address):
        try:
            print(f"{Fore.YELLOW}[*] Looking up domains for {ip_address}...{Style.RESET_ALL}")
            
            hostname = socket.getfqdn(ip_address)
            domains = [hostname] if hostname != ip_address else []
            
            try:
                response = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip_address}", timeout=5)
                if response.status_code == 200 and len(response.text) > 0 and "error" not in response.text.lower():
                    domains_from_api = response.text.strip().split('\n')
                    domains.extend(domains_from_api)
            except requests.RequestException:
                pass
            
            domains = list(set([d for d in domains if d != ip_address and d.strip()]))
            
            return domains
        except Exception as e:
            print(f"{Fore.RED}[!] Error retrieving domains: {str(e)}{Style.RESET_ALL}")
            return []
    
    def get_ip_from_domain(self, domain):
        try:
            print(f"{Fore.YELLOW}[*] Looking up IP address for domain {domain}...{Style.RESET_ALL}")
            ip_address = socket.gethostbyname(domain)
            print(f"{Fore.GREEN}[+] IP address for {domain}: {ip_address}{Style.RESET_ALL}")
            return ip_address
        except socket.gaierror:
            print(f"{Fore.RED}[!] Could not resolve domain {domain} to IP address{Style.RESET_ALL}")
            return None
        except Exception as e:
            print(f"{Fore.RED}[!] Error retrieving IP for domain: {str(e)}{Style.RESET_ALL}")
            return None
    
    def get_whois_info(self, query):
        try:
            print(f"{Fore.YELLOW}[*] Looking up WHOIS information for {query}...{Style.RESET_ALL}")
            whois_info = whois.whois(query)
            return whois_info
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
            return None
    
    def format_date(self, date_obj):
        """Format date objects to string"""
        if isinstance(date_obj, list):
            return [self.format_date(d) for d in date_obj if d]
        elif isinstance(date_obj, datetime):
            return date_obj.strftime("%Y-%m-%d %H:%M:%S")
        return str(date_obj) if date_obj else "Not available"
    
    def display_info(self, info, query, is_ip=False):
        """
        Format and display WHOIS information
        
        Args:
            info (dict): WHOIS information dictionary
            query (str): The domain or IP that was queried
            is_ip (bool): True if the query is an IP address
        """
        if not info:
            print(f"{Fore.RED}[!] Could not retrieve WHOIS information.{Style.RESET_ALL}")
            return
        
        query_type = "IP ADDRESS" if is_ip else "DOMAIN"
        print(f"\n{Back.BLUE}{Fore.WHITE} {query_type} INFORMATION {Style.RESET_ALL}\n")
        print(f"{Fore.CYAN}Query:{Style.RESET_ALL} {query}")
        
        if not is_ip:
            ip = self.get_ip_from_domain(query)
            if ip:
                print(f"{Fore.CYAN}IP Address:{Style.RESET_ALL} {ip}")
        
        print(f"\n{Back.BLUE}{Fore.WHITE} KEY INFORMATION {Style.RESET_ALL}\n")
        
        if hasattr(info, 'registrant') or hasattr(info, 'org') or hasattr(info, 'organization'):
            org = info.org if hasattr(info, 'org') else (info.organization if hasattr(info, 'organization') else 'Not available')
            print(f"{Fore.CYAN}Organization:{Style.RESET_ALL} {org}")
        
        if hasattr(info, 'registrar') and info.registrar:
            print(f"{Fore.CYAN}Registrar:{Style.RESET_ALL} {info.registrar}")
        
        if hasattr(info, 'creation_date') and info.creation_date:
            print(f"{Fore.CYAN}Created:{Style.RESET_ALL} {self.format_date(info.creation_date)}")
        
        if hasattr(info, 'expiration_date') and info.expiration_date:
            print(f"{Fore.CYAN}Expires:{Style.RESET_ALL} {self.format_date(info.expiration_date)}")
        
        if hasattr(info, 'name_servers') and info.name_servers and not is_ip:
            name_servers = info.name_servers if isinstance(info.name_servers, list) else [info.name_servers]
            if len(name_servers) > 3:
                name_servers = name_servers[:3]
                print(f"{Fore.CYAN}Name Servers:{Style.RESET_ALL} {', '.join(name_servers)} (+ more)")
            else:
                print(f"{Fore.CYAN}Name Servers:{Style.RESET_ALL} {', '.join(name_servers)}")
        
        if hasattr(info, 'emails') and info.emails:
            emails = info.emails if isinstance(info.emails, list) else [info.emails]
            if len(emails) > 1:
                print(f"{Fore.CYAN}Contact:{Style.RESET_ALL} {emails[0]} (+ more)")
            else:
                print(f"{Fore.CYAN}Contact:{Style.RESET_ALL} {emails[0]}")
        
        print(f"\n{Fore.YELLOW}[?] Show full WHOIS details? (y/n):{Style.RESET_ALL} ", end="")
        try:
            show_details = input().strip().lower()
            if show_details == 'y':
                excluded_keys = ['emails', 'name_servers']
                
                print(f"\n{Back.BLUE}{Fore.WHITE} COMPLETE WHOIS INFORMATION {Style.RESET_ALL}\n")
                for key, value in info.items():
                    if value and key not in excluded_keys:
                        formatted_value = value
                        if isinstance(value, list):
                            formatted_value = ", ".join(str(v) for v in value if v)
                        elif isinstance(value, datetime):
                            formatted_value = self.format_date(value)
                        
                        print(f"{Fore.CYAN}{key}:{Style.RESET_ALL} {formatted_value}")
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Detailed view cancelled.{Style.RESET_ALL}")
    
    def save_to_file(self, info, query, format_type="txt", is_ip=False):
        """
        Save WHOIS information to a file
        
        Args:
            info (dict): WHOIS information
            query (str): The domain or IP that was queried
            format_type (str): Output format (txt or json)
            is_ip (bool): True if the query is an IP address
        """
        query_type = "ip" if is_ip else "domain"
        filename = f"{query}_whois.{format_type}"
        
        try:
            if format_type == "json":
                data_to_save = {
                    "query": query,
                    "query_type": query_type,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "data": {}
                }
                
                for key, value in info.items():
                    if isinstance(value, datetime):
                        data_to_save["data"][key] = self.format_date(value)
                    elif isinstance(value, list) and value and isinstance(value[0], datetime):
                        data_to_save["data"][key] = self.format_date(value)
                    else:
                        data_to_save["data"][key] = value
                
                with open(filename, 'w', encoding='utf-8') as file:
                    json.dump(data_to_save, file, indent=2, default=str)
            else:
                with open(filename, 'w', encoding='utf-8') as file:
                    file.write(f"WHOIS INFORMATION FOR {query_type.upper()} {query}\n")
                    file.write("="*50 + "\n\n")
                    
                    if not is_ip:
                        try:
                            ip = socket.gethostbyname(query)
                            file.write(f"IP Address: {ip}\n\n")
                        except:
                            pass
                    else:
                        domains = self.get_domains_from_ip(query)
                        if domains:
                            file.write("Associated Domains:\n")
                            for domain in domains[:10]:
                                file.write(f"- {domain}\n")
                            if len(domains) > 10:
                                file.write(f"- ... and {len(domains) - 10} more\n")
                            file.write("\n")
                    
                    file.write("KEY INFORMATION\n")
                    file.write("-"*30 + "\n")
                    
                    if hasattr(info, 'registrar') and info.registrar:
                        file.write(f"Registrar: {info.registrar}\n")
                    
                    if hasattr(info, 'org') or hasattr(info, 'organization'):
                        org = info.org if hasattr(info, 'org') else (info.organization if hasattr(info, 'organization') else None)
                        if org:
                            file.write(f"Organization: {org}\n")
                    
                    if hasattr(info, 'creation_date') and info.creation_date:
                        file.write(f"Created: {self.format_date(info.creation_date)}\n")
                    
                    if hasattr(info, 'expiration_date') and info.expiration_date:
                        file.write(f"Expires: {self.format_date(info.expiration_date)}\n")
                    
                    file.write("\n")
                    
                    file.write("COMPLETE WHOIS DATA\n")
                    file.write("-"*30 + "\n")
                    for key, value in info.items():
                        if value:
                            formatted_value = value
                            if isinstance(value, list):
                                formatted_value = ", ".join(str(v) for v in value if v)
                            elif isinstance(value, datetime):
                                formatted_value = self.format_date(value)
                            file.write(f"{key}: {formatted_value}\n")
            
            print(f"{Fore.GREEN}[+] Saved to {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving file: {str(e)}{Style.RESET_ALL}")
    
    def process_query(self, query, save=False, output_format="txt"):
        """
        Process a query which can be either a domain or IP address
        
        Args:
            query (str): The domain name or IP address to query
            save (bool): Whether to save results to a file
            output_format (str): Output format for saving (txt or json)
        """
        is_ip = self.is_ip_address(query)
        
        if is_ip:
            print(f"{Fore.GREEN}[+] Detected IP address: {query}{Style.RESET_ALL}")
            
            domains = self.get_domains_from_ip(query)
            if domains:
                display_domains = domains[:5]
                remaining = len(domains) - 5 if len(domains) > 5 else 0
                
                print(f"{Fore.GREEN}[+] Found {len(domains)} domain(s) for IP {query}:{Style.RESET_ALL}")
                for idx, domain in enumerate(display_domains, 1):
                    print(f"  {idx}. {domain}")
                if remaining > 0:
                    print(f"  ... and {remaining} more")
                
                if len(domains) > 0:
                    try:
                        print(f"{Fore.YELLOW}[?] Query WHOIS for a domain instead? (y/n): {Style.RESET_ALL}", end="")
                        choice = input().lower()
                        
                        if choice == 'y':
                            print(f"{Fore.YELLOW}[?] Enter domain number (1-{len(display_domains)}): {Style.RESET_ALL}", end="")
                            domain_idx = int(input())
                            
                            if 1 <= domain_idx <= len(display_domains):
                                selected_domain = display_domains[domain_idx-1]
                                print(f"{Fore.GREEN}[+] Selected: {selected_domain}{Style.RESET_ALL}")
                                
                                whois_info = self.get_whois_info(selected_domain)
                                if whois_info:
                                    self.display_info(whois_info, selected_domain, is_ip=False)
                                    
                                    if save:
                                        self.save_to_file(whois_info, selected_domain, output_format, is_ip=False)
                                
                                return
                    except (ValueError, IndexError):
                        print(f"{Fore.RED}[!] Invalid selection, continuing with IP lookup{Style.RESET_ALL}")
                    except KeyboardInterrupt:
                        print(f"\n{Fore.YELLOW}[*] Selection cancelled{Style.RESET_ALL}")
            
            whois_info = self.get_whois_info(query)
            if whois_info:
                self.display_info(whois_info, query, is_ip=True)
                
                if save:
                    self.save_to_file(whois_info, query, output_format, is_ip=True)
        else:
            print(f"{Fore.GREEN}[+] Detected domain: {query}{Style.RESET_ALL}")
            
            whois_info = self.get_whois_info(query)
            if whois_info:
                self.display_info(whois_info, query, is_ip=False)
                
                if save:
                    self.save_to_file(whois_info, query, output_format, is_ip=False)
    
    def run(self):
        """Main program flow"""
        parser = argparse.ArgumentParser(description='Domain & IP WHOIS Lookup Tool')
        parser.add_argument('query', help='Domain name or IP address to lookup (e.g., example.com or 8.8.8.8)')
        parser.add_argument('-o', '--output', choices=['txt', 'json'], default='txt',
                            help='Output file format (default: txt)')
        parser.add_argument('-s', '--save', action='store_true', 
                            help='Save results to a file')
        
        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)
            
        args = parser.parse_args()
        
        self.banner()
        
        query = args.query.strip()
        if not query:
            print(f"{Fore.RED}[!] Invalid query format. Example: example.com or 8.8.8.8{Style.RESET_ALL}")
            sys.exit(1)
        
        self.process_query(query, args.save, args.output)


if __name__ == "__main__":
    try:
        whois_tool = WhoisTool()
        whois_tool.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Program terminated by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error: {str(e)}{Style.RESET_ALL}")
