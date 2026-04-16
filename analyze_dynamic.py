"""phishAI 동적 분석 모듈

Docker 샌드박스(AI 에이전트 또는 레거시)로 동적 분석을 수행하고,
Docker가 없으면 curl 정적 DOM 분석으로 폴백한다.
"""

import json
from pathlib import Path


def run_dynamic_analysis(domain: str, edir: Path) -> dict:
    """동적 분석을 수행하고 결과를 반환한다.

    Returns:
        {"dom_analysis": dict, "dynamic_analysis": dict}
    """
    print("[*] 사이트 분석 중...")
    dom_result = {}
    dynamic_result = {}

    try:
        from ti_clients.site_analyzer import SiteAnalyzer
        sa = SiteAnalyzer(edir)

        if sa.docker:
            print("  [Docker] 동적 분석 실행...")
            dynamic_result = sa.dynamic_analyze(f"https://{domain}")

            if "error" not in dynamic_result:
                service = dynamic_result.get("service", "Docker")
                # AI 동적 분석 결과
                if dynamic_result.get("site_type"):
                    print(f"  [{service}] ✓ 유형: {dynamic_result['site_type']}, "
                          f"스텝: {dynamic_result.get('rounds_completed', 0)}회")
                # 레거시 동적 분석 결과
                else:
                    pages = dynamic_result.get("pages", [])
                    print(f"  [{service}] ✓ {len(pages)}개 페이지 분석 완료")
                    if pages:
                        dom_result = {
                            "external_domains": pages[0].get("external_domains", []),
                            "external_scripts": pages[0].get("external_scripts", []),
                            "iframes": pages[0].get("iframes", []),
                        }
            else:
                print(f"  [Docker] ⚠ {dynamic_result.get('error')} → curl 정적 분석으로 폴백")
                dom_result = sa.collect_dom(f"https://{domain}")
        else:
            print("  [curl] 정적 DOM 분석...")
            dom_result = sa.collect_dom(f"https://{domain}")

        if "error" not in dom_result:
            print(f"  [DOM] ✓ 외부 도메인 {len(dom_result.get('external_domains', []))}개")
            if dom_result.get("platform"):
                print(f"  [플랫폼] {json.dumps(dom_result['platform'], ensure_ascii=False)}")
        elif dom_result.get("error"):
            print(f"  [DOM] ⚠ {dom_result.get('error')}")

    except Exception as e:
        print(f"  [사이트분석] ⚠ {e}")

    return {
        "dom_analysis": {k: v for k, v in dom_result.items() if k != "service"} if dom_result else {},
        "dynamic_analysis": {k: v for k, v in dynamic_result.items() if k != "service"} if dynamic_result else {},
    }
