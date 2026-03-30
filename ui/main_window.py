from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QFileDialog, QLineEdit
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# ── collector / parser 임포트 ────────────────────────────────────────────────
from collectors import userassist_collector
from parsers import userassist_parser


# ── 백그라운드 수집 워커 ─────────────────────────────────────────────────────
class AnalysisWorker(QThread):
    """
    UI가 멈추지 않도록 수집·파싱을 별도 스레드에서 실행한다.
    작업이 끝나면 result_ready 시그널로 결과를 전달한다.
    """
    result_ready = pyqtSignal(list)   # 파싱 완료 데이터
    log_message  = pyqtSignal(str)    # 진행 로그
    error        = pyqtSignal(str)    # 오류 메시지

    def run(self):
        try:
            self.log_message.emit("[INFO] UserAssist 수집 중...")
            raw = userassist_collector.collect()
            self.log_message.emit(f"[INFO] 원시 데이터 {len(raw)}건 수집 완료")

            self.log_message.emit("[INFO] 파싱 중...")
            entries = userassist_parser.parse(raw)
            self.log_message.emit(f"[INFO] 파싱 완료 – {len(entries)}건")

            self.result_ready.emit(entries)

        except Exception as e:
            self.error.emit(f"[ERROR] 수집 실패: {e}")


# ── 메인 윈도우 ──────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Forensic Analysis Tool")
        self.setGeometry(100, 100, 1000, 700)

        self.image_path = None
        self.worker = None          # QThread 참조 보관 (GC 방지)

        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()

        # 🔹 타이틀
        title = QLabel("디지털 포렌식 분석 도구")
        title.setFont(QFont("맑은 고딕", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

        # 🔹 중간 영역 (좌/우)
        middle_layout = QHBoxLayout()

        # =========================
        # 📂 좌측 패널
        # =========================
        left_layout = QVBoxLayout()

        self.select_image_btn = QPushButton("📁 이미지 파일 선택 (.E01 / .dd)")
        self.select_image_btn.clicked.connect(self.select_image)
        left_layout.addWidget(self.select_image_btn)

        self.image_label = QLabel("선택된 이미지: 없음")
        left_layout.addWidget(self.image_label)

        self.mount_label = QLabel("마운트 경로 입력 (예: E:\\)")
        left_layout.addWidget(self.mount_label)

        self.mount_input = QLineEdit()
        self.mount_input.setPlaceholderText("예: E:\\")
        left_layout.addWidget(self.mount_input)

        self.run_btn = QPushButton("🚀 분석 시작")
        self.run_btn.clicked.connect(self.run_analysis)
        left_layout.addWidget(self.run_btn)

        left_layout.addStretch()

        left_widget = QWidget()
        left_widget.setLayout(left_layout)
        left_widget.setFixedWidth(320)

        # =========================
        # 📊 우측 패널 (결과)
        # =========================
        right_layout = QVBoxLayout()

        result_title = QLabel("분석 결과")
        result_title.setFont(QFont("맑은 고딕", 12, QFont.Bold))
        right_layout.addWidget(result_title)

        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)
        right_layout.addWidget(self.result_output)

        right_widget = QWidget()
        right_widget.setLayout(right_layout)

        # 좌우 합치기
        middle_layout.addWidget(left_widget)
        middle_layout.addWidget(right_widget)

        main_layout.addLayout(middle_layout)

        # =========================
        # 🧾 로그 영역
        # =========================
        log_title = QLabel("로그")
        log_title.setFont(QFont("맑은 고딕", 11, QFont.Bold))
        main_layout.addWidget(log_title)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setFixedHeight(150)
        main_layout.addWidget(self.log_output)

        # 전체 적용
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        self.apply_style()

    # ──────────────────────────────────────────────────────────────────────────
    # 📁 이미지 선택
    # ──────────────────────────────────────────────────────────────────────────
    def select_image(self):
        file, _ = QFileDialog.getOpenFileName(
            self, "이미지 파일 선택", "",
            "Image Files (*.E01 *.dd *.raw)"
        )
        if file:
            self.image_path = file
            self.image_label.setText(f"선택된 이미지: {file}")
            self.log("[INFO] 이미지 선택 완료")

    # ──────────────────────────────────────────────────────────────────────────
    # ▶ 분석 실행
    # ──────────────────────────────────────────────────────────────────────────
    def run_analysis(self):
        mount_path = self.mount_input.text().strip()

        if not self.image_path:
            self.log("[ERROR] 이미지 파일을 선택하세요")
            return
        if not mount_path:
            self.log("[ERROR] 마운트 경로를 입력하세요")
            return

        self.log("[INFO] 분석 시작")
        self.log(f"[INFO] 마운트 경로: {mount_path}")

        # 버튼 비활성화 (중복 실행 방지)
        self.run_btn.setEnabled(False)
        self.result_output.clear()

        # ── UserAssist 수집을 QThread로 실행 ──────────────────────────────────
        self.worker = AnalysisWorker()
        self.worker.log_message.connect(self.log)
        self.worker.result_ready.connect(self.on_analysis_done)
        self.worker.error.connect(self.on_analysis_error)
        self.worker.finished.connect(lambda: self.run_btn.setEnabled(True))
        self.worker.start()

    # ──────────────────────────────────────────────────────────────────────────
    # ✅ 수집 완료 콜백
    # ──────────────────────────────────────────────────────────────────────────
    def on_analysis_done(self, entries: list):
        """파싱된 UserAssist 엔트리를 결과 패널에 출력한다."""
        if not entries:
            self.result_output.setText("수집된 UserAssist 항목이 없습니다.")
            return

        lines = ["=== UserAssist 분석 결과 ===\n"]
        for e in entries:
            ts = e["last_run_time"].strftime("%Y-%m-%d %H:%M:%S UTC") \
                 if e["last_run_time"] else "알 수 없음"
            lines.append(
                f"[{e['guid_type']}] {e['name']}\n"
                f"  실행 횟수: {e['run_count']}  |  세션: {e['session_id']}  |  마지막 실행: {ts}\n"
            )

        self.result_output.setText("\n".join(lines))
        self.log(f"[INFO] 결과 표시 완료 – {len(entries)}건")

    # ──────────────────────────────────────────────────────────────────────────
    # ❌ 오류 콜백
    # ──────────────────────────────────────────────────────────────────────────
    def on_analysis_error(self, msg: str):
        self.log(msg)
        self.result_output.setText(msg)

    # ──────────────────────────────────────────────────────────────────────────
    # 🧾 로그 출력
    # ──────────────────────────────────────────────────────────────────────────
    def log(self, message: str):
        self.log_output.append(message)

    # ──────────────────────────────────────────────────────────────────────────
    # 🎨 스타일
    # ──────────────────────────────────────────────────────────────────────────
    def apply_style(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #f5f6f7;
                color: #222;
                font-size: 13px;
            }
            QPushButton {
                background-color: #4a90e2;
                color: white;
                border-radius: 6px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #357abd;
            }
            QPushButton:disabled {
                background-color: #a0b8d8;
            }
            QTextEdit {
                background-color: #ffffff;
                border: 1px solid #ccc;
                border-radius: 5px;
            }
            QLineEdit {
                background-color: #ffffff;
                border: 1px solid #ccc;
                border-radius: 5px;
                padding: 5px;
            }
            QLabel {
                margin-top: 5px;
            }
        """)