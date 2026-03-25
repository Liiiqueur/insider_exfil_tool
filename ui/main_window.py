from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QFileDialog, QLineEdit
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Forensic Analysis Tool")
        self.setGeometry(100, 100, 1000, 700)

        self.image_path = None

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

        # 🎨 스타일 적용
        self.apply_style()

    # 📁 이미지 선택
    def select_image(self):
        file, _ = QFileDialog.getOpenFileName(
            self,
            "이미지 파일 선택",
            "",
            "Image Files (*.E01 *.dd *.raw)"
        )

        if file:
            self.image_path = file
            self.image_label.setText(f"선택된 이미지: {file}")
            self.log("[INFO] 이미지 선택 완료")

    # ▶ 분석 실행
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

        # 🔥 이후 collector 연결
        # ex) events = collect_files(mount_path)

        # 더미 결과
        self.result_output.setText(
            "=== 분석 결과 ===\n\n"
            "파일 접근 이벤트: 120건\n"
            "USB 연결 이벤트: 1건\n"
            "의심 점수: 70점\n"
        )

        self.log("[INFO] 분석 완료")

    # 🧾 로그 출력
    def log(self, message):
        self.log_output.append(message)

    # 🎨 화이트 테마 스타일
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