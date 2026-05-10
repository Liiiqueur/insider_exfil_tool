# Windows 내부자 정보유출 포렌식 수사 보조 도구

Windows 포렌식 이미지에서 주요 아티팩트를 수집하고, 내부자 정보유출 정황을 빠르게 탐색하기 위한 Python 기반 GUI 도구입니다.

## 핵심 기능

- 포렌식 이미지 열람 및 볼륨/파일 시스템 탐색
- `$MFT` 직접 파싱 기반 파일 시스템 메타데이터 분석
- 파일 Hex, Text, Metadata 미리보기
- 선택한 파일 추출
- 주요 Windows 아티팩트 수집 및 파싱
- 공통 이벤트 포맷 기반 통합 타임라인 생성
- 타임라인 상세 정보에서 파일 시스템 경로 및 오프셋 연동
- 결과 요약, Raw JSON, Parsed Table 형태로 확인
- 결과 텍스트 내보내기

## 지원 아티팩트

- `$MFT`, `$J`
- LNK
- Event Log
- RecentDocs
- Browser History
- UserAssist
- Jumplist
- Shellbags
- MountedDevices
- USB Devices
- Print Spool
- Prefetch
- Amcache
- OST/PST (Outlook)

## 실행 방법

```bash
cd insider_exfil_tool
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

## 요구 사항

- Python 3.x
- Windows 환경
- `PyQt5`
- `pytsk3`
- `python-registry`
- `regipy`
- `libpff-python`

## 최근 반영 사항

- 아티팩트별 타임라인 이벤트 포맷 통일
- 메인 UI 내 `Timeline` 탭 기반 탐색 화면 추가
- 연/월/일 단위 타임라인 집계 및 기본 활동 필터 지원
- 타임라인 상세 정보에서 파일 시스템 탭과 Hex 오프셋 선택 연동
- 타임라인 및 `$MFT` 파싱 결과 캐시 적용으로 재열기 성능 개선

## 폴더 구조

```text
insider_exfil_tool/
├─ collectors/   # 아티팩트 수집
├─ parsers/      # 아티팩트 파싱
├─ ui/           # PyQt5 UI
├─ main.py       # 실행 진입점
└─ requirements.txt
```
