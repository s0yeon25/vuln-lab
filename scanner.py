import nmap

def run_asm_scanner(target_ip):
    nm = nmap.PortScanner()
    
    print(f"[*] {target_ip} 대상 Attack Surface(공격 표면) 정찰 시작...")
    
    # 취약한 서비스들이 몰려있는 포트 대역 조사
    # 웹 포트(9080~9082)와 실제 내부 포트(1445 등)를 한 번에 스캔
    nm.scan(target_ip, ports='135-145, 445, 1445, 9080-9085', arguments='-sV -O')
    
    for host in nm.all_hosts():
        print(f"\n[+] 발견된 타겟 호스트: {host}")
        
        # 1. OS 추정 결과 출력
        if 'osmatch' in nm[host] and nm[host]['osmatch']:
            print(f"   [ OS 추정]: {nm[host]['osmatch'][0]['name']} (정확도: {nm[host]['osmatch'][0]['accuracy']}%)")
        
        # 2. 열린 포트 및 서비스 식별
        for proto in nm[host].all_protocols():
            ports = sorted(nm[host][proto].keys())
            for port in ports:
                state = nm[host][proto][port]['state']
                if state == 'open':
                    service_name = nm[host][proto][port]['name']
                    product = nm[host][proto][port]['product']
                    version = nm[host][proto][port]['version']
                    
                    print(f"   [OPEN PORT]: {port}/{proto}")
                    print(f"      - 서비스 유형: {service_name}")
                    print(f"      - 프로그램/버전: {product} {version}")
                    print("      " + "-"*30)

if __name__ == "__main__":
    target = "127.0.0.1" 
    run_asm_scanner(target)