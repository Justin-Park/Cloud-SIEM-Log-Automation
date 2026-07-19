import re
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

LOG_FILE = "server_auth.log"
REPORT_FILE = "siem_report.html"
FAILED_THRESHOLD = 3
TIME_WINDOW_MINUTES = 5

# [보안 설정] 이메일 알림 설정을 위한 가상 정보
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
ADMIN_EMAIL = "security-admin@company.com" # 알림을 받을 관리자 이메일

def send_security_alert(ip, start_time, end_time, count):
    """위협 탐지 시 관리자에게 즉시 긴급 보안 경보 메일을 발송하는 함수"""
    print(f"🚀 [ALERT NOTIFIER] 긴급 이메일 경보 발송 준비 중... (대상: {ADMIN_EMAIL})")
    
    subject = f"🚨 [CRITICAL ALERT] 인프라 내 Brute Force 공격 징후 탐지 ({ip})"
    body = f"""
    [긴급 보안 경보] 본 시스템에서 실시간 침해 시도가 탐지되었습니다.
    
    ■ 위협 유형: Brute Force Attack (무단 접근 시도)
    ■ 위협 소스 IP: {ip}
    ■ 공격 탐지 구간: {start_time} ~ {end_time}
    ■ 위험도 단계: CRITICAL (5분 내 {count}회 연속 로그인 실패)
    
    즉시 해당 IP의 방화벽 차단(ACL 적용) 및 해당 계정의 패스워드 강제 변경 조치를 취해주시기 바랍니다.
    본 메일은 SIEM 자동 관제 엔진에 의해 발송되었습니다.
    """
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = "siem-engine@company.com"
    msg['To'] = ADMIN_EMAIL
    
    # 팁: 실제 연동 시에는 smtplib.SMTP를 통해 계정 인증 후 발송하게 됩니다.
    # 여기서는 시뮬레이션을 위해 이메일 포맷 구성 및 발송 로그 출력으로 대체합니다.
    print(f"📧 [이메일 발송 완료] 제목: {subject}")

def analyze_and_dispatch():
    print("🔍 [SIEM 관제 엔진 v1.2] 실시간 탐지 및 알림 엔진을 구동합니다...")
    
    ip_failure_timelines = {}
    
    with open(LOG_FILE, "r") as f:
        for line in f:
            if "login failed" in line:
                time_match = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                ip_match = re.search(r"from IP (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                
                if time_match and ip_match:
                    log_time = datetime.strptime(time_match.group(1), "%Y-%m-%d %H:%M:%S")
                    ip = ip_match.group(1)
                    
                    if ip not in ip_failure_timelines:
                        ip_failure_timelines[ip] = []
                    ip_failure_timelines[ip].append(log_time)

    attack_events = []
    for ip, times in ip_failure_timelines.items():
        times.sort()
        for i in range(len(times) - FAILED_THRESHOLD + 1):
            window_start = times[i]
            window_end = times[i + FAILED_THRESHOLD - 1]
            time_difference = (window_end - window_start).total_seconds() / 60
            
            if time_difference <= TIME_WINDOW_MINUTES:
                start_str = window_start.strftime("%Y-%m-%d %H:%M:%S")
                end_str = window_end.strftime("%Y-%m-%d %H:%M:%S")
                
                attack_events.append({
                    "ip": ip, "start": start_str, "end": end_str, "count": len(times)
                })
                
                # [핵심] 위협 탐지 즉시 경보 알림 함수 호출!
                send_security_alert(ip, start_str, end_str, len(times))
                break

    # HTML 리포트 생성 로직
    html_content = f"""<!DOCTYPE html>
<html>
<head><title>🚨 SIEM 위협 분석 리포트</title></head>
<body>
    <h1>🛡️ Cloud SIEM 관제 대시보드</h1>
    <p>탐지된 총 위협: {len(attack_events)}건</p>
</body>
</html>"""
    with open(REPORT_FILE, "w") as f:
        f.write(html_content)

if __name__ == "__main__":
    analyze_and_dispatch()
