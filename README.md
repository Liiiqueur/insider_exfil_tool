# 😎 Windows 내부자 정보유출 포렌식 수사 보조 도구

Windows 포렌식 이미지에서 주요 아티팩트를 수집하고, **가중치 기반 행위 패턴/위험도 분석**을 통해 내부자 정보유출 정황을 빠르게 탐색하기 위한 Python 기반 GUI 도구입니다.

<br />

## 핵심 기능

- 포렌식 이미지 열람 및 볼륨/파일 시스템 탐색
- 파일 시스템 메타데이터 분석
- 파일 Hex, Text, Metadata 미리보기
- 선택한 파일 추출
- 주요 Windows 아티팩트 수집 및 파싱
- 통합 타임라인 생성
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

## ⚡ 실행 방법

```bash
cd insider_exfil_tool
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

<br />

## ✅ 요구 사항

- Python `3.9+` (권장: `3.10`)
- Windows OS (`Windows 10` 이상 권장)
- `PyQt5 5.15`
- `pytsk3 20231007`
- `python-registry 1.3`
- `regipy 5.2`
- `libpff-python` (환경별 최신 안정 버전 권장)


<br />

## 📁 폴더 구조

```text
insider_exfil_tool/
├─ collectors/       # 아티팩트 수집
├─ parsers/          # 아티팩트 파싱
├─ core/             # 행위 패턴/위험도 분석
├─ ui/               # PyQt5 UI
├─ image_handler.py  # 포렌식 이미지/FS 접근 핸들러
├─ main.py           # 실행 진입점
├─ setup.bat         # Windows 실행 보조 스크립트
└─ requirements.txt
```
