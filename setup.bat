@echo off

echo [1/3] 가상환경 생성...
python -m venv .venv

echo [2/3] 가상환경 활성화...
call .venv\Scripts\activate

echo [3/3] 패키지 설치...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo.
echo 설정 완료!
pause