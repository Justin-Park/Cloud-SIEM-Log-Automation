import re
from collections import Counter

# 1. 분석할 로그 파일 경로와 공격으로 간주할 임계치 설정
LOG_FILE = "server_auth.log"
FAILED_THRESHOLD = 3

def analyze_logs():
    print("🔍 [SIEM 기본 엔진] 인프라 접근 로그 분석을 시작합니다...")
    
    # 실패한 공격자 IP를 모아둘 리스트
    failed_ips = []
    
    # 2. 로그 파일 정규식 파싱
    # WARN 등급이면서 login failed가 발생한 라인의 IP 패턴을 추출합니다.
    with open(LOG_FILE, "r") as f:
        for line in f:
            if "login failed" in line:
                # 라인 안에서 IP 주소 포맷(숫자.숫자.숫자.숫자)을 검색
                match = re.search(r"from IP (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                if match:
                    failed_ips.append(match.group(1))
    
    # 3. IP별 실패 횟수 카운트
    ip_counts = Counter(failed_ips)
    
    # 4. 임계치를 넘은 위험 IP 추출 및 경고 출력
    detected_attacks = 0
    for ip, count in ip_counts.items():
        if count >= FAILED_THRESHOLD:
            print(f"🚨 [ALERT] 무단 접근 공격 탐지! 위협 IP: {ip} (로그인 실패 횟수: {count}회)")
            detected_attacks += 1
            
    if detected_attacks == 0:
        print("✅ 분석 완료: 탐지된 이상 징후가 없습니다.")

if __name__ == "__main__":
    analyze_logs()
