import socket
import struct
import sys
import os
import csv
import datetime
from collections import defaultdict

PACKET_COUNTERS = defaultdict(int)

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
    Extrai informação da query DNS ou resposta DNS.
    """
    try:
        # Cabeçalho DNS com 12 bytes fixo:
        # Bytes 0-1: ID (identificador único para a query) (H)
        # Bytes 2-3: Flags - bit 0x8000 = QR (1=resposta, 0=pergunta) (H)
        # Bytes 4-5: QDCOUNT (número de questions) (H)
        # Bytes 6-7: ANCOUNT (número de answers) (H)
        # Bytes 8-9: NSCOUNT (número de nameservers) (H)
        # Bytes 10-11: ARCOUNT (número de additional records) (H)
        header = struct.unpack('!HHHHHH', payload[:12])
        flags_word = header[1]
        qdcount = header[2]
        ancount = header[3]
        
        # Bit QR (0x8000): 1 = resposta, 0 = pergunta
        is_response = (flags_word & 0x8000) != 0
        
        if qdcount == 0:
            return "Pacote DNS (sem query)"

        offset = 12
        (query_name, offset) = _dns_parse_name(payload, offset)
        
        q_header = struct.unpack('!HH', payload[offset:offset+4])
        qtype = q_header[0]
        offset += 4 
        
        qtype_map = {
            1: 'A',
            28: 'AAAA',
            5: 'CNAME',
            15: 'MX',
            16: 'TXT',
            12: 'PTR',
            2: 'NS'
        }
        qtype_str = qtype_map.get(qtype, f'Tipo {qtype}')

        if not is_response:
            return f"Query ({qtype_str}): {query_name}"

        if ancount == 0:
            return f"Resposta para ({qtype_str}) {query_name} (sem respostas)"

        (answer_name, offset) = _dns_parse_name(payload, offset)
        
        # Answer Record com 10 bytes:
        # Bytes 0-1: Type (H) - tipo de record
        # Bytes 2-3: Class (H) - classe (sempre 1 para IN)
        # Bytes 4-7: TTL (I) - tempo de vida em segundos
        # Bytes 8-9: RDLength (H) - tamanho dos dados de resposta
        ans_header = struct.unpack('!HHIH', payload[offset:offset+10])
        ans_type = ans_header[0]
        ans_rdlength = ans_header[3]
        offset += 10
        
        rdata = payload[offset : offset + ans_rdlength]

        if ans_type == 1:
            ip = socket.inet_ntoa(rdata)
            return f"Resposta (A): {answer_name} -> {ip}"
        
        elif ans_type == 28:
            ip = socket.inet_ntop(socket.AF_INET6, rdata)
            return f"Resposta (AAAA): {answer_name} -> {ip}"
            
        elif ans_type == 5:
            (cname, _) = _dns_parse_name(payload, offset)
            return f"Resposta (CNAME): {answer_name} -> {cname}"
        
        else:
            ans_type_str = qtype_map.get(ans_type, f'Tipo {ans_type}')
            return f"Resposta ({ans_type_str}) para ({qtype_str}) {query_name}"

    except Exception as e:
        return f"Erro ao parsear DNS: {e}"
    
def _dns_parse_name(payload, offset):
    """
    Decodifica um nome DNS (ex: 'www.google.com').
    Formato: cada label é prefixado por seu tamanho em 1 byte.
    Exemplo binário: 3www6google3com0 = www.google.com
    03 77 77 77 06 67 6f 6f 67 6c 65 03 63 6f 6d 00
    
    Retorna (nome_decodificado, novo_offset_apos_nome)
    """
    name_parts = []
    original_offset = offset
    followed_pointer = False

    while True:
        # Byte atual: tamanho da label ou flag de ponteiro
        length = payload[offset]
        
        # Tamanho 0 = fim do nome (byte terminador)
        if length == 0:
            offset += 1
            break
        
        # Ponteiro de compressão: padrão 11xxxxxx (0xC0)
        # Os 14 bits restantes formam um offset para outro lugar no pacote
        if (length & 0xC0) == 0xC0:
            # Lê 2 bytes: 11xxxxxx (bits altos) + 8 bits (bits baixos)
            pointer_offset = struct.unpack('!H', payload[offset:offset+2])[0]
            # Máscara para remover os 2 bits de flag e obter o offset real
            pointer_offset &= 0x3FFF
            
            # Recursão para ler o nome apontado (não avança offset principal)
            (pointed_name, _) = _dns_parse_name(payload, pointer_offset)
            name_parts.append(pointed_name)
            
            offset += 2
            followed_pointer = True
            break
        else:
            offset += 1
            name_parts.append(payload[offset : offset + length].decode('latin-1'))
            offset += length
    
    # Retorna nome e novo offset (diferente se foi ponteiro)
    if followed_pointer:
        return (".".join(name_parts), original_offset + 2)
    else:
        return (".".join(name_parts), offset)
    
def parse_icmp(payload):
    """
    Extrai informações do ICMP.
    """
    try:
        if len(payload) < 8:
            return ""
        
        # Cabeçalho ICMP:
        # Byte 0: Tipo
        # Byte 1: Código
        # Bytes 2-3: Checksum
        icmp_type = payload[0]
        icmp_code = payload[1]
        
        icmp_types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            4: 'Source Quench',
            5: 'Redirect',
            8: 'Echo Request',
            11: 'Time Exceeded',
            12: 'Parameter Problem'
        }
        
        type_name = icmp_types.get(icmp_type, f'Type {icmp_type}')
        return f"{type_name} (Code {icmp_code})"
    except:
        return ""

def parse_icmpv6(payload):
    """
    Extrai informações do ICMPv6.
    """
    try:
        if len(payload) < 8:
            return ""
        
        icmp_type = payload[0]
        icmp_code = payload[1]
        
        icmpv6_types = {
            1: 'Destination Unreachable',
            2: 'Packet Too Big',
            3: 'Time Exceeded',
            4: 'Parameter Problem',
            128: 'Echo Request',
            129: 'Echo Reply',
            133: 'Router Solicitation',
            134: 'Router Advertisement',
            135: 'Neighbor Solicitation',
            136: 'Neighbor Advertisement'
        }
        
        type_name = icmpv6_types.get(icmp_type, f'Type {icmp_type}')
        return f"{type_name} (Code {icmp_code})"
    except:
        return ""

def parse_http(payload):
    """
    Extrai informação de requisição ou resposta HTTP.
    """
    try:
        http_data = payload.decode('latin-1')
        first_line = http_data.split('\r\n')[0]

        # Requisição HTTP: METODO /caminho HTTP/versao
        # Ex: GET /index.html HTTP/1.1
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
        for method in methods:
            if first_line.startswith(method):
                parts = first_line.split(' ')
                if len(parts) >= 2:
                    return f"{parts[0]} {parts[1]}"
        
        # Resposta HTTP: HTTP/versao codigo mensagem
        # Ex: HTTP/1.1 200 OK
        if first_line.startswith('HTTP/'):
            return first_line

        return "Fragmento HTTP"
    except Exception:
        return "Payload HTTP (binário/malformado)"

def init_csv_files():
    """
    Cria os arquivos CSV e escreve os cabeçalhos se não existirem.
    """
    csv_files = {
        'net': ('camada_internet.csv', ['Data/Hora', 'Protocolo', 'IP Origem', 'IP Destino', 'Protocolo Superior', 'Outras Informações', 'Tamanho']),
        'trans': ('camada_transporte.csv', ['Data/Hora', 'Protocolo', 'IP Origem', 'Porta Origem', 'IP Destino', 'Porta Destino', 'Tamanho']),
        'app': ('camada_aplicacao.csv', ['Data/Hora', 'Protocolo', 'Informações do Protocolo'])
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
    # Limpa o terminal (funciona em Linux/Unix/Mac)
    os.system('clear')
    
    print("="*50) 
    print(f"--- 🛰️ ATUALIZAÇÃO DO MONITOR @ {get_timestamp()} ---")
    print(f"Monitorando interface: {sys.argv[1]}\n")
    print("Contagem de Pacotes por Protocolo:")
    print("-----------------------------------")
    
    if not PACKET_COUNTERS:
        print("Aguardando pacotes...")
    
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

def parse_application_layer(payload, ip_src, ip_dst, size, protocol_name, writers):
    """
    Loga protocolos da camada de aplicação.
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
    elif protocol_name == 'DHCP':
        details = "Pacote DHCP"
    elif protocol_name == 'NTP':
        details = "Sincronização de tempo NTP"
    
    if protocol_name != 'Outro':
        log_data = [timestamp, protocol_name, details]
        writers['app'].writerow(log_data)


def parse_transport_layer(payload, ip_src, ip_dst, size, protocol_id, writers):
    """
    Decodifica TCP e UDP (Camada 4).
    """
    timestamp = get_timestamp()
    
    try:
        if protocol_id == 6:
            PACKET_COUNTERS['TCP'] += 1
            # Cabeçalho TCP com 20 bytes mínimo:
            # Bytes 0-1: Porta origem (H)
            # Bytes 2-3: Porta destino (H)
            # Bytes 4-7: Número sequência (L)
            # Bytes 8-11: Número confirmação (L)
            # Bytes 12-13: Data Offset (4 bits) + Flags (12 bits) (H)
            # Bytes 14-15: Window size (H)
            # Bytes 16-17: Checksum (H)
            # Bytes 18-19: Urgent pointer (H)
            header = struct.unpack('!HHLLHHHH', payload[:20])
            src_port = header[0]
            dst_port = header[1]
            
            # Data Offset está nos 4 bits superiores do campo offset_flags
            # Valor em palavras de 32 bits, multiplicar por 4 para bytes
            offset_flags = header[4]
            tcp_header_len = ((offset_flags >> 12) & 0xF) * 4
            l7_payload = payload[tcp_header_len:]

            log_data = [timestamp, 'TCP', ip_src, src_port, ip_dst, dst_port, size]
            writers['trans'].writerow(log_data)
            
            app_proto = get_app_protocol(src_port, dst_port)
            parse_application_layer(l7_payload, ip_src, ip_dst, size, app_proto, writers)

        elif protocol_id == 17:
            PACKET_COUNTERS['UDP'] += 1
            # Cabeçalho UDP com 8 bytes fixo:
            # Bytes 0-1: Porta origem (H)
            # Bytes 2-3: Porta destino (H)
            # Bytes 4-5: Tamanho total (H)
            # Bytes 6-7: Checksum (H)
            header = struct.unpack('!HHHH', payload[:8])
            src_port = header[0]
            dst_port = header[1]
            
            l7_payload = payload[8:]
            
            log_data = [timestamp, 'UDP', ip_src, src_port, ip_dst, dst_port, size]
            writers['trans'].writerow(log_data)

            app_proto = get_app_protocol(src_port, dst_port)
            parse_application_layer(l7_payload, ip_src, ip_dst, size, app_proto, writers)
            
    except struct.error:
        PACKET_COUNTERS['Transport Error'] += 1

def parse_network_layer(raw_packet, writers):
    """
    Decodifica camada de rede: IPv4, IPv6, ICMP, ICMPv6.
    Assume que raw_packet começa diretamente no cabeçalho IP.
    """
    timestamp = get_timestamp()
    
    # Detecta a versão do IP pelo primeiro byte (4 bits superiores)
    try:
        version = (raw_packet[0] >> 4) & 0xF
    except (IndexError, struct.error):
        PACKET_COUNTERS['Network Error'] += 1
        return

    # IPv4 (versão 4)
    if version == 4:
        PACKET_COUNTERS['IPv4'] += 1
        
        try:
            header_data = raw_packet[:20]
            
            # Cabeçalho IPv4 com 20 bytes mínimo:
            # Byte 0: Versão (4 bits) + IHL (4 bits) (B)
            # Byte 1: Type of Service (B)
            # Bytes 2-3: Tamanho total (H)
            # Bytes 4-5: Identificação (H)
            # Bytes 6-7: Flags (3 bits) + Fragment Offset (13 bits) (H)
            # Byte 8: Time to Live (B)
            # Byte 9: Protocolo (TCP=6, UDP=17, ICMP=1) (B)
            # Bytes 10-11: Header checksum (H)
            # Bytes 12-15: IP origem (4s)
            # Bytes 16-19: IP destino (4s)
            header = struct.unpack('!BBHHHBBH4s4s', header_data)
            
            version_ihl = header[0]
            total_size = header[2]
            protocol_id = header[6]
            ip_src = format_ipv4(header[8])
            ip_dst = format_ipv4(header[9])
            
            ihl_bytes = (version_ihl & 0xF) * 4
            ip_payload = raw_packet[ihl_bytes:]

            # Identifica protocolo superior
            protocol_names = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH'}
            protocol_name = protocol_names.get(protocol_id, str(protocol_id))
            
            if protocol_id == 1:
                PACKET_COUNTERS['ICMP'] += 1
                icmp_info = parse_icmp(ip_payload)
                log_data = [timestamp, 'ICMP', ip_src, ip_dst, protocol_name, icmp_info, total_size]
                writers['net'].writerow(log_data)
            else:
                log_data = [timestamp, 'IPv4', ip_src, ip_dst, protocol_name, '', total_size]
                writers['net'].writerow(log_data)
                parse_transport_layer(ip_payload, ip_src, ip_dst, total_size, protocol_id, writers)

        except struct.error:
            PACKET_COUNTERS['IPv4 Error'] += 1

    # IPv6 (versão 6)
    elif version == 6:
        PACKET_COUNTERS['IPv6'] += 1
        
        try:
            header_data = raw_packet[:40]
            
            # Cabeçalho IPv6 com 40 bytes fixo:
            # Bytes 0-3: Versão (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits) (L)
            # Bytes 4-5: Payload Length (H)
            # Byte 6: Next Header (protocolo) (B)
            # Byte 7: Hop Limit (B)
            # Bytes 8-23: IP origem (16 bytes)
            # Bytes 24-39: IP destino (16 bytes)
            payload_size = struct.unpack('!H', header_data[4:6])[0]
            protocol_id = header_data[6]
            ip_src = format_ipv6(header_data[8:24])
            ip_dst = format_ipv6(header_data[24:40])
            
            total_size = 40 + payload_size
            
            ip_payload = raw_packet[40:]
            
            protocol_names = {6: 'TCP', 17: 'UDP', 58: 'ICMPv6', 41: 'IPv6', 43: 'Routing', 44: 'Fragment'}
            protocol_name = protocol_names.get(protocol_id, str(protocol_id))
            
            # ICMPv6 (Next Header 58): não encapsula protocolos superiores
            if protocol_id == 58:
                PACKET_COUNTERS['ICMPV6'] += 1
                icmpv6_info = parse_icmpv6(ip_payload)
                log_data = [timestamp, 'ICMPv6', ip_src, ip_dst, protocol_name, icmpv6_info, total_size]
                writers['net'].writerow(log_data)
            else:
                log_data = [timestamp, 'IPv6', ip_src, ip_dst, protocol_name, '', total_size]
                writers['net'].writerow(log_data)
                parse_transport_layer(ip_payload, ip_src, ip_dst, total_size, protocol_id, writers)
            
        except struct.error:
            PACKET_COUNTERS['IPv6 Error'] += 1

    # Versão IP desconhecida
    else:
        PACKET_COUNTERS['Unknown IP Version'] += 1




def main():
    if os.geteuid() != 0:
        print("Erro: Este script deve ser executado como root (use sudo).")
        print("Raw sockets requerem privilégios de administrador.")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Erro: Forneça o nome da interface de rede.")
        print(f"Exemplo: sudo {sys.argv[0]} enp4s0")
        sys.exit(1)
        
    interface_name = sys.argv[1]
    csv_files, csv_writers = init_csv_files()

    try:
        # AF_PACKET: acesso à camada de enlace (Ethernet raw)
        # SOCK_RAW: captura pacote completo, sem headers do SO
        # ntohs(0x0003): ETH_P_ALL = todos os protocolos
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((interface_name, 0))
    except socket.error as e:
        print(f"Erro ao criar socket na interface '{interface_name}': {e}")
        print("Verifique se o nome da interface está correto (use: ip addr ou ifconfig)")
        sys.exit(1)
    except PermissionError:
         print("Erro de Permissão. Tem certeza que executou com 'sudo'?")
         sys.exit(1)

    print(f"--- 🛰️ Iniciando monitor na interface '{interface_name}' ---")
    print("Capturando pacotes da camada de rede...")
    print("Protocolos suportados: IP, IPv6, ICMP, ICMPv6")
    print("Pressione Ctrl+C para parar.")
    print("Gerando logs: camada_internet.csv, camada_transporte.csv, camada_aplicacao.csv")
    
    packet_count_since_ui_update = 0

    try:
        while True:
            raw_packet, addr = s.recvfrom(65535)
            
            if len(raw_packet) > 0:
                # Tenta detectar versão IP no primeiro byte
                first_byte = raw_packet[0]
                ip_version = (first_byte >> 4) & 0xF
                
                # Se os 4 bits superiores são 4 ou 6, é um pacote IP direto
                if ip_version == 4 or ip_version == 6:
                    # Pacote começa direto no IP (camada de rede)
                    parse_network_layer(raw_packet, csv_writers)
                elif len(raw_packet) > 14:
                    # Pode ter cabeçalho Ethernet, tenta extrair EtherType
                    try:
                        ethertype = struct.unpack('!H', raw_packet[12:14])[0]
                        # 0x0800 = IPv4, 0x86DD = IPv6
                        if ethertype == 0x0800 or ethertype == 0x86DD:
                            # Pula o cabeçalho Ethernet (14 bytes)
                            ip_packet = raw_packet[14:]
                            parse_network_layer(ip_packet, csv_writers)
                    except:
                        pass
            
            packet_count_since_ui_update += 1
            if packet_count_since_ui_update >= 1:
                update_text_ui()
                packet_count_since_ui_update = 0
                for f in csv_files.values():
                    f.flush()

    except KeyboardInterrupt:
        print("\n--- Parando o monitor ---")
    except Exception as e:
        print(f"\nErro inesperado: {e}")
    finally:
        s.close()
        for f in csv_files.values():
            f.close()
        print("Socket e arquivos fechados. Encerrando.")
        update_text_ui()


if __name__ == "__main__":
    main()
