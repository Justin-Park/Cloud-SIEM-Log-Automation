import urllib.request
import json

def analyze_with_ai(ip, failure_count, start_time, end_time):
    """SIEM에서 탐지된 위협 데이터를 AI SOC 분석관에게 보내 소견을 받는 함수"""
    print(f"🤖 [AI SOC Analyst] {ip} 위협 데이터 심층 분석 중...")
    
    prompt = f"""
    당신은 10년 차 Senior SOC(보안관제) 분석관입니다.
    다음 SIEM 탐지 이벤트를 바탕으로 관제 요원이 즉시 조치할 수 있는 보고서를 한국어로 요약하세요.

    [탐지 데이터]
    - 공격 소스 IP: {ip}
    - 로그인 실패 횟수: {failure_count}회
    - 공격 구간: {start_time} ~ {end_time}

    [응답 양식]
    1. 위협 평가 (위험도 및 한 줄 요약)
    2. 권장 조치 사항 (방화벽 iptables 차단 명령어 포함)
    """

    url = "http://localhost:11434/api/generate"
    payload = {
        "model": "qwen2.5:1.5b",
        "prompt": prompt,
        "stream": False
    }

    try:
        req = urllib.request.Request(
            url, 
            data=json.dumps(payload).encode('utf-8'), 
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode('utf-8'))
            return result['response']
    except Exception as e:
        return f"❌ AI 연동 에러 발생: {e}"

if __name__ == "__main__":
    # 테스트용 데이터 실행
    ai_report = analyze_with_ai("203.0.113.5", 5, "2026-08-26 14:00:00", "2026-08-26 14:04:30")
    print("\n================ [ AI SOC 관제 리포트 ] ================")
    print(ai_report)
    print("=========================================================")
