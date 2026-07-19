import re
from datetime import datetime

LOG_FILE = "server_auth.log"
REPORT_FILE = "siem_report.html"
FAILED_THRESHOLD = 3
TIME_WINDOW_MINUTES = 5

def analyze_and_generate_report():
    print("🔍 [SIEM 관제 엔진] 시간 윈도우 분석 및 대시보드 생성을 시작합니다...")
    
    ip_failure_timelines = {}
    
    # 1. 로그 파싱
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

    # 2. 공격 탐지 및 결과 수집
    attack_events = []
    for ip, times in ip_failure_timelines.items():
        times.sort()
        for i in range(len(times) - FAILED_THRESHOLD + 1):
            window_start = times[i]
            window_end = times[i + FAILED_THRESHOLD - 1]
            time_difference = (window_end - window_start).total_seconds() / 60
            
            if time_difference <= TIME_WINDOW_MINUTES:
                attack_events.append({
                    "ip": ip,
                    "start": window_start.strftime("%Y-%m-%d %H:%M:%S"),
                    "end": window_end.strftime("%Y-%m-%d %H:%M:%S"),
                    "count": len(times)
                })
                break

    # 3. HTML 대시보드 보고서 생성
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>🚨 SIEM 위협 분석 리포트</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 40px; background-color: #f5f7fa; }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }}
        .summary {{ background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); margin-bottom: 30px; }}
        .alert-card {{ background: #fff1f0; border-left: 5px solid #ff4d4f; padding: 15px; margin: 15px 0; border-radius: 4px; }}
        .badge {{ background: #ff4d4f; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>🛡️ Cloud SIEM 실시간 위협 관제 대시보드</h1>
    <div class="summary">
        <h3>📊 분석 요약</h3>
        <p><strong>분석 대상 로그:</strong> {LOG_FILE}</p>
        <p><strong>탐지된 총 위협 시나리오:</strong> <span class="badge">{len(attack_events)}건</span></p>
        <p><strong>발행 시각:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>

    <h2>🚨 탐지된 침해 시도 내역</h2>
    """

    if not attack_events:
        html_content += "<p style='color: green;'>✅ 현재 인프라 내에 탐지된 이상 징후가 없습니다.</p>"
    else:
        for event in attack_events:
            html_content += f"""
            <div class="alert-card">
                <p><strong>🔥 위협 유형:</strong> Brute Force (무단 접근 공격)</p>
                <p><strong>🎯 공격 소스 IP:</strong> <span style="color:#d32f2f; font-weight:bold;">{event['ip']}</span></p>
                <p><strong>⏱️ 공격 타임프레임:</strong> {event['start']} ~ {event['end']}</p>
                <p><strong>🔢 해당 구간 실패 횟수:</strong> {event['count']}회 연속 실패</p>
            </div>
            """

    html_content += """
</body>
</html>
"""

    with open(REPORT_FILE, "w") as f:
        f.write(html_content)
        
    print(f"✅ 대시보드 리포트 생성 완료: {REPORT_FILE}")

if __name__ == "__main__":
    analyze_and_generate_report()
