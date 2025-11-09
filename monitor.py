#!/usr/bin/env python3
import socket
import struct
import sys
import os
import csv
import datetime
from collections import defaultdict

# Dicionário de contadores para a UI
PACKET_COUNTERS = defaultdict(int)

# --- Funções Auxiliares de Formatação ---

def get_timestamp():
    """Retorna o timestamp atual formatado."""
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def format_mac(addr_bytes):
    """Formata um endereço MAC de bytes para string."""
    return ":".join(f"{b:02x}" for b in addr_bytes)

def format_ipv4(addr_bytes):
    """Formata um endereço IPv4 de bytes para string."""
    return socket.inet_ntoa(addr_bytes)

def format_ipv6(addr_bytes):
    """Formata um endereço IPv6 de bytes para string."""
    return socket.inet_ntop(socket.AF_INET6, addr_bytes)


def parse_dns(payload):
    """
    Decodifica o payload da camada 7 como DNS (binário).
    Extrai o nome da query da primeira pergunta (Question).
    """
    try:
        # O cabeçalho DNS tem 12 bytes
        # Unpack: ! (Network Byte Order)
        # H (unsigned short, 2 bytes) x 6
        # (ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
        header = struct.unpack('!HHHHHH', payload[:12])
        qdcount = header[2]  # Question Count
        
        # Se não houver perguntas, é uma resposta ou outro tipo de pacote
        if qdcount == 0:
            return "Resposta DNS"

        # Pula o cabeçalho de 12 bytes para encontrar a query
        offset = 12
        query_name = ""
        
        # Loop para decodificar o nome da query
        # O formato é: 3www6google3com0
        while True:
            # Pega o tamanho da próxima label (ex: 3 para "www")
            length = payload[offset]
            
            # Se o tamanho for 0, é o fim do nome
            if length == 0:
                offset += 1 # Pular o byte nulo
                break
                
            # Detecção de ponteiro de compressão DNS (0xc0)
            # Se os 2 primeiros bits são 11, é um ponteiro
            if (length & 0xc0) == 0xc0:
                # Um parser completo seguiria o ponteiro,
                # mas para este log, apenas indicamos que ele existe.
                query_name += "<ponteiro>"
                offset += 2 # Pular os 2 bytes do ponteiro
                break

            # É uma label normal
            offset += 1 # Pular o byte de tamanho
            # Lê o pedaço do nome (ex: "www")
            query_name += payload[offset : offset + length].decode('latin-1') + "."
            offset += length

        # Remove o último "." (ex: "www.google.com.")
        return f"Query: {query_name.rstrip('.')}"

    except Exception:
        return "Erro ao parsear DNS"
    
def parse_http(payload):
    """
    Tenta decodificar o payload da camada 7 como HTTP (baseado em texto).
    Procura por métodos de requisição (ex: 'GET /') ou 
    códigos de resposta (ex: 'HTTP/1.1 200 OK').
    """
    try:
        # Decodifica o payload. 'latin-1' é seguro e não quebra em bytes inválidos.
        http_data = payload.decode('latin-1')
        
        # Pega a primeira linha (ex: "GET /index.html HTTP/1.1")
        first_line = http_data.split('\r\n')[0]

        # Verifica se é uma requisição HTTP
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
        for method in methods:
            if first_line.startswith(method):
                parts = first_line.split(' ')
                if len(parts) >= 2:
                    # Retorna "GET /index.html"
                    return f"{parts[0]} {parts[1]}"
        
        # Verifica se é uma resposta HTTP
        if first_line.startswith('HTTP/'):
            # Retorna "HTTP/1.1 200 OK"
            return first_line

        return "Fragmento HTTP"
    except Exception:
        # Falha se for um pacote TCP que não é texto (ex: fragmentado)
        return "Payload HTTP (binário/malformado)"

# --- Funções de UI e Log ---

def init_csv_files():
    """
    Cria os arquivos CSV e escreve os cabeçalhos se não existirem.
    """
    csv_files = {
        'net': ('camada_internet.csv', ['Data/Hora', 'Protocolo', 'IP Origem', 'IP Destino', 'Protocolo Superior', 'Tamanho']),
        'trans': ('camada_transporte.csv', ['Data/Hora', 'Protocolo', 'IP Origem', 'Porta Origem', 'IP Destino', 'Porta Destino', 'Tamanho']),
        'app': ('camada_aplicacao.csv', ['Data/Hora', 'Protocolo', 'IP Origem', 'IP Destino', 'Detalhes', 'Tamanho'])
    }
    
    writers = {}
    files = {}

    try:
        for key, (filename, headers) in csv_files.items():
            # Verifica se o arquivo está vazio para escrever o cabeçalho
            write_header = not os.path.exists(filename) or os.path.getsize(filename) == 0
            
            # Abre o arquivo em modo 'append' (a)
            f = open(filename, 'a', newline='', encoding='utf-8')
            writer = csv.writer(f)
            
            if write_header:
                writer.writerow(headers)
            
            files[key] = f
            writers[key] = writer
            
        return files, writers
    except IOError as e:
        print(f"Erro ao abrir ou escrever nos arquivos CSV: {e}")
        print("Verifique as permissões de escrita no diretório.")
        sys.exit(1)


def update_text_ui():
    """Limpa a tela e exibe os contadores de pacotes."""
    # Usar 'clear' ou 'cls' pode ser disruptivo. 
    # Vamos apenas imprimir blocos novos.
    # os.system('clear') 
    print("\n" + "="*50) 
    print(f"--- 🛰️ ATUALIZAÇÃO DO MONITOR @ {get_timestamp()} ---")
    print(f"Monitorando interface: {sys.argv[1]}\n")
    print("Contagem de Pacotes por Protocolo:")
    print("-----------------------------------")
    
    if not PACKET_COUNTERS:
        print("Aguardando pacotes...")
    
    # Ordena os contadores por contagem (maior primeiro)
    sorted_counters = sorted(
        PACKET_COUNTERS.items(), 
        key=lambda item: item[1], 
        reverse=True
    )
    
    for proto, count in sorted_counters:
        print(f"| {proto:<10}: {count:>10}")
        
    print("-----------------------------------")
    print("\nPressione Ctrl+C para parar.")
    print("-----------------------------------")
    print("="*50 + "\n")


def get_app_protocol(src_port, dst_port):
    """Identifica protocolos de aplicação baseados em portas conhecidas."""
    if src_port == 80 or dst_port == 80:
        return 'HTTP'
    if src_port == 53 or dst_port == 53:
        return 'DNS'
    if (src_port == 67 or dst_port == 67 or
        src_port == 68 or dst_port == 68):
        return 'DHCP'
    if src_port == 123 or dst_port == 123:
        return 'NTP'
    if src_port == 443 or dst_port == 443:
        return 'HTTPS'
    return 'Outro'

# --- Funções Principais de Parsing ---

def parse_application_layer(payload, ip_src, ip_dst, size, protocol_name, writers):
    """
    Loga protocolos da camada de aplicação e chama parsers de DPI.
    [cite_start][cite: 38-43]
    """
    PACKET_COUNTERS[protocol_name] += 1
    
    timestamp = get_timestamp()
    details = "" 

    if protocol_name == 'HTTP':
        details = parse_http(payload)
    elif protocol_name == 'DNS':
        details = parse_dns(payload)
    elif protocol_name == 'HTTPS':
        details = "Tráfego Criptografado (TLS)"
    
    if protocol_name != 'Outro':
        # Log com a nova coluna de detalhes
        log_data = [timestamp, protocol_name, ip_src, ip_dst, details, size]
        writers['app'].writerow(log_data)
    # --- FIM DA MODIFICAÇÃO ---


def parse_transport_layer(payload, ip_src, ip_dst, size, protocol_id, writers):
    """
    Decodifica TCP e UDP (Camada 4) e loga no CSV.
    """
    timestamp = get_timestamp()
    
    try:
        # Protocolo 6 = TCP
        if protocol_id == 6:
            PACKET_COUNTERS['TCP'] += 1
            # Unpack: !H H L L H H H H
            header = struct.unpack('!HHLLHHHH', payload[:20])
            src_port = header[0]
            dst_port = header[1]
            
            # --- MODIFICAÇÃO AQUI ---
            # Encontrar o payload real da Camada 7
            # O "Data Offset" (em palavras de 4 bytes) está nos 4 bits
            # mais altos do 5º H (índice 4)
            offset_flags = header[4]
            tcp_header_len = ((offset_flags >> 12) & 0xF) * 4
            l7_payload = payload[tcp_header_len:] # Payload real da aplicação
            # --- FIM DA MODIFICAÇÃO ---

            # Log de Transporte
            log_data = [timestamp, 'TCP', ip_src, src_port, ip_dst, dst_port, size]
            writers['trans'].writerow(log_data)
            
            # Verificar Camada de Aplicação
            app_proto = get_app_protocol(src_port, dst_port)
            parse_application_layer(l7_payload, ip_src, ip_dst, size, app_proto, writers) # Passa o l7_payload

        # Protocolo 17 = UDP
        elif protocol_id == 17:
            PACKET_COUNTERS['UDP'] += 1
            # Unpack: !H H H H (Cabeçalho UDP tem 8 bytes fixos)
            header = struct.unpack('!HHHH', payload[:8])
            src_port = header[0]
            dst_port = header[1]
            
            # --- MODIFICAÇÃO AQUI ---
            l7_payload = payload[8:] # Payload real da aplicação
            # --- FIM DA MODIFICAÇÃO ---
            
            # Log de Transporte
            log_data = [timestamp, 'UDP', ip_src, src_port, ip_dst, dst_port, size]
            writers['trans'].writerow(log_data)

            # Verificar Camada de Aplicação
            app_proto = get_app_protocol(src_port, dst_port)
            parse_application_layer(l7_payload, ip_src, ip_dst, size, app_proto, writers) # Passa o l7_payload
            
    except struct.error:
        # Pacote malformado ou muito pequeno
        PACKET_COUNTERS['Transport Error'] += 1

def parse_network_layer(packet_data, writers):
    """
    Decodifica a Camada de Rede (IPv4, IPv6, ICMP).
    [cite: 23-28]
    """
    timestamp = get_timestamp()

    # --- Parse IPv4 ---
    # EtherType 0x0800 = IPv4
    if packet_data['ethertype'] == 0x0800:
        PACKET_COUNTERS['IPv4'] += 1
        
        try:
            # Pegar os primeiros 20 bytes do cabeçalho IP
            header_data = packet_data['payload'][:20]
            
            # Unpack: !B B H H H B B H 4s 4s
            #           (Ver/IHL, ToS, Tam. Total, ID, Flags/Offset, TTL, Proto, Checksum, IP Src, IP Dst)
            header = struct.unpack('!BBHHHBBH4s4s', header_data)
            
            version_ihl = header[0]
            # ihl = (version_ihl & 0xF) * 4  # Comprimento do cabeçalho
            total_size = header[2]     # Tamanho total do pacote IP
            protocol_id = header[6]    # Protocolo Superior (TCP=6, UDP=17, ICMP=1)
            ip_src = format_ipv4(header[8])
            ip_dst = format_ipv4(header[9])
            
            # Pega o payload (dados depois do cabeçalho IP)
            ihl_bytes = (version_ihl & 0xF) * 4
            ip_payload = packet_data['payload'][ihl_bytes:]

            # Log da Camada de Rede (IPv4)
            log_data = [timestamp, 'IPv4', ip_src, ip_dst, protocol_id, total_size]
            writers['net'].writerow(log_data)
            
            # --- Parse ICMP (baseado em IPv4) ---
            if protocol_id == 1:
                PACKET_COUNTERS['ICMP'] += 1
                # ICMP não tem "Protocolo Superior" no log de exemplo [cite: 73]
                log_data_icmp = [timestamp, 'ICMP', ip_src, ip_dst, '', total_size]
                writers['net'].writerow(log_data_icmp)
            
            # Enviar para a camada de transporte
            else:
                parse_transport_layer(ip_payload, ip_src, ip_dst, total_size, protocol_id, writers)

        except struct.error:
            PACKET_COUNTERS['IPv4 Error'] += 1

    # --- Parse IPv6 ---
    # EtherType 0x86DD = IPv6
    elif packet_data['ethertype'] == 0x86DD:
        PACKET_COUNTERS['IPv6'] += 1
        
        try:
            # Cabeçalho IPv6 tem 40 bytes fixos
            header_data = packet_data['payload'][:40]
            
            # Unpack: !L H B 16s 16s
            # (Ver/Traffic/Flow, Tam. Payload, Próx. Header, IP Src, IP Dst)
            # Vamos desempacotar só o que precisamos
            payload_size = struct.unpack('!H', header_data[4:6])[0]
            protocol_id = header_data[6]  # "Next Header" é o análogo ao "Protocolo"
            ip_src = format_ipv6(header_data[8:24])
            ip_dst = format_ipv6(header_data[24:40])
            
            # Tamanho total = 40 (cabeçalho) + tamanho do payload
            total_size = 40 + payload_size
            
            # Log da Camada de Rede (IPv6)
            log_data = [timestamp, 'IPv6', ip_src, ip_dst, protocol_id, total_size]
            writers['net'].writerow(log_data)
            
            # Pega o payload (dados depois do cabeçalho IP)
            ip_payload = packet_data['payload'][40:]
            
            # --- Parse ICMPv6 (baseado em IPv6) ---
            # O "Next Header" para ICMPv6 é 58
            if protocol_id == 58:
                PACKET_COUNTERS['ICMPV6'] += 1 # Contamos como 'ICMP6'
                # ICMP não tem "Protocolo Superior" no log de exemplo [cite: 73]
                log_data_icmp = [timestamp, 'ICMPV6', ip_src, ip_dst, '', total_size]
                writers['net'].writerow(log_data_icmp)
            
            # Enviar para a camada de transporte (TCP, UDP, etc.)
            else:
                # Nota: O trabalho de labredes lidaria com "extension headers" aqui,
                # mas para este subset, tratamos o "Next Header" como o protocolo L4.
                parse_transport_layer(ip_payload, ip_src, ip_dst, total_size, protocol_id, writers)
            
            # --- CORREÇÃO TERMINA AQUI ---
            
        except struct.error:
            PACKET_COUNTERS['IPv6 Error'] += 1

    # Outros protocolos da camada de rede (ex: ARP)
    else:
        # EtherTypes como 0x0806 (ARP) caem aqui
        PACKET_COUNTERS['Outro (L2)'] += 1


def parse_link_layer(packet_bytes, writers):
    """
    Decodifica o frame Ethernet (Camada 2) e envia para a camada de rede.
    """
    try:
        # Cabeçalho Ethernet tem 14 bytes:
        # 6 (MAC Dst) + 6 (MAC Src) + 2 (EtherType)
        header = struct.unpack('!6s6sH', packet_bytes[:14])
        
        packet_data = {
            'mac_dst': format_mac(header[0]),
            'mac_src': format_mac(header[1]),
            'ethertype': header[2],      # ex: 0x0800 (IPv4), 0x86DD (IPv6)
            'payload': packet_bytes[14:] # Dados para a próxima camada (L3)
        }
        
        parse_network_layer(packet_data, writers)
        
    except struct.error:
        # Pacote muito pequeno ou malformado
        PACKET_COUNTERS['Link Error'] += 1


# --- Função Principal ---

def main():
    # 1. Verificar privilégios de root 
    if os.geteuid() != 0:
        print("Erro: Este script deve ser executado como root (use sudo).")
        print("Raw sockets requerem privilégios de administrador.")
        sys.exit(1)

    # 2. Verificar argumento de linha de comando [cite: 48, 49]
    if len(sys.argv) < 2:
        print("Erro: Forneça o nome da interface de rede.")
        print(f"Exemplo: sudo {sys.argv[0]} enp4s0")
        sys.exit(1)
        
    interface_name = sys.argv[1]

    # 3. Inicializar arquivos CSV
    csv_files, csv_writers = init_csv_files()

    # 4. Criar o Raw Socket [cite: 6]
    try:
        # socket.AF_PACKET: Permite acesso à camada de enlace (Link Layer)
        # socket.SOCK_RAW:   Queremos o pacote "cru"
        # socket.ntohs(0x0003): ETH_P_ALL, captura todos os protocolos
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        
        # 5. Vincular (bind) à interface de rede especificada
        s.bind((interface_name, 0))
    except socket.error as e:
        print(f"Erro ao criar ou vincular o socket na interface '{interface_name}': {e}")
        print("Verifique se o nome da interface está correto (ex: use 'ip addr' ou 'ifconfig').")
        sys.exit(1)
    except PermissionError:
         print("Erro de Permissão. Tem certeza que executou com 'sudo'?")
         sys.exit(1)

    print(f"--- 🛰️ Iniciando monitor na interface '{interface_name}' ---")
    print("Capturando pacotes... Pressione Ctrl+C para parar.")
    print("Gerando logs: camada_internet.csv, camada_transporte.csv, camada_aplicacao.csv")
    
    packet_count_since_ui_update = 0

    try:
        while True:
            # 6. Receber os dados do pacote
            # 65535 é o tamanho máximo do buffer
            raw_packet, addr = s.recvfrom(65535)
            
            # 7. Iniciar o processo de parsing (Camada 2)
            parse_link_layer(raw_packet, csv_writers)
            
            packet_count_since_ui_update += 1
            
            # 8. Atualizar logs e UI
            # Atualiza a UI a cada 1 pacote para feedback rápido
            if packet_count_since_ui_update >= 1:
                update_text_ui()
                packet_count_since_ui_update = 0
                
                # Garante que os logs sejam escritos em disco [cite: 44]
                for f in csv_files.values():
                    f.flush()

    except KeyboardInterrupt:
        print("\n--- 🛑 Parando o monitor ---")
        
    except Exception as e:
        print(f"\nErro inesperado: {e}")
        
    finally:
        # 9. Fechar socket e arquivos
        s.close()
        for f in csv_files.values():
            f.close()
        print("Socket e arquivos fechados. Encerrando.")
        # Imprime os contadores finais
        update_text_ui()


if __name__ == "__main__":
    main()