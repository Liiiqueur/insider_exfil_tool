# Windows 내부자 정보유출 포렌식 수사 보조 도구

Windows 포렌식 이미지에서 주요 아티팩트를 수집하고, 내부자 정보유출 정황을 빠르게 탐색하기 위한 Python 기반 GUI 도구입니다.

<br />

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

<br />

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

<br />

## 실행 방법

```bash
cd insider_exfil_tool
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

<br />

## 요구 사항

- Python 3.x
- Windows OS
- `PyQt5`
- `pytsk3`
- `python-registry`
- `regipy`
- `libpff-python`

<br />

## 최근 반영 사항

- 시작 화면을 `새 사건 / 사건 열기` 중심의 Case Flow로 개편
- 최근 사건 목록 표시 및 저장된 사건 불러오기 보강
- `caseflow_window.py`를 `ui/windows.py`로 통합
- 경고/오류/상태바 메시지 한국어 정비
- `Artifact Results` 탭 개선
  - 좌측: 아티팩트 목록 + 건수 + 위험 뱃지
  - 중앙: 이벤트 테이블(시간, 행위, 대상, 요약)
  - 우측: 이벤트 상세(경로, 시간, 출처 등 핵심 필드)
- LNK/EventLog/USB 아티팩트 전용 상세 필드 템플릿 적용
- 타임라인 및 `$MFT` 파싱 캐시 기반 재열기 성능 개선

<br />

## 폴더 구조

```text
insider_exfil_tool/
├─ collectors/   # 아티팩트 수집
├─ parsers/      # 아티팩트 파싱
├─ ui/           # PyQt5 UI
├─ main.py       # 실행 진입점
└─ requirements.txt
```
