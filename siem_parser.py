import re
from datetime import datetime

LOG_FILE = "server_auth.log"
FAILED_THRESHOLD = 3
TIME_WINDOW_MINUTES = 5  # 5분 이내 연속 실패를 탐지

def analyze_logs_with_time():
    print("🔍 [SIEM 고도화 엔진] 시간 윈도우 기반 무단 접근(Brute Force) 분석을 시작합니다...")
    
    # IP별로 실패한 시각(datetime)을 기록할 딕셔너리 { ip: [time1, time2, ...] }
    ip_failure_timelines = {}
    
    with open(LOG_FILE, "r") as f:
        for line in f:
            if "login failed" in line:
                # 1. 로그에서 시간(정규식 앞부분)과 IP를 동시에 추출
                # 예: 2026-07-14 06:05:20
                time_match = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                ip_match = re.search(r"from IP (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                
                if time_match and ip_match:
                    log_time = datetime.strptime(time_match.group(1), "%Y-%m-%d %H:%M:%S")
                    ip = ip_match.group(1)
                    
                    if ip not in ip_failure_timelines:
                        ip_failure_timelines[ip] = []
                    ip_failure_timelines[ip].append(log_time)

    # 2. 시간 윈도우 검증 알고리즘
    detected_attacks = 0
    for ip, times in ip_failure_timelines.items():
        times.sort() # 시간 순 정렬
        
        # 연속된 실패 기록들을 비교하여 5분 이내에 3번 이상 실패했는지 확인
        for i in range(len(times) - FAILED_THRESHOLD + 1):
            window_start = times[i]
            window_end = times[i + FAILED_THRESHOLD - 1]
            
            # 두 실패 간의 시간 차이 계산
            time_difference = (window_end - window_start).total_seconds() / 60
            
            if time_difference <= TIME_WINDOW_MINUTES:
                print(f"🚨 [ALERT] 5분 이내 임계치 초과 Brute Force 공격 탐지!")
                print(f"   - 위협 IP: {ip}")
                print(f"   - 공격 탐지 구간: {window_start} ~ {window_end}")
                detected_attacks += 1
                break # 한 IP당 하나의 대표 얼럿만 출력
                
    if detected_attacks == 0:
        print("✅ 분석 완료: 지정된 시간 내에 발생한 이상 징후가 없습니다.")

if __name__ == "__main__":
    analyze_logs_with_time()
