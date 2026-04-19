import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from PyQt5.QtCore import QThread, pyqtSignal
from .constants import ARTIFACT_RUNNERS
from image_handler import ImageHandler


class LoadImageWorker(QThread):
    done    = pyqtSignal(object)   # ImageHandler
    log_msg = pyqtSignal(str)
    error   = pyqtSignal(str)

    def __init__(self, path: str):
        super().__init__()
        self.path = path

    def run(self):
        try:
            self.log_msg.emit(f"[INFO] opening image: {self.path}")
            handler = ImageHandler()
            handler.open(self.path)
            if not handler.volumes:
                self.error.emit("[ERROR] no readable volume found")
                return
            self.done.emit(handler)
        except Exception as exc:
            self.error.emit(f"[ERROR] image open failed: {exc}")


class ListDirWorker(QThread):

    done  = pyqtSignal(list, object)   # entries, tree_item
    error = pyqtSignal(str)

    def __init__(self, handler: ImageHandler, fs, inode, path: str, tree_item):
        super().__init__()
        self.handler   = handler
        self.fs        = fs
        self.inode     = inode
        self.path      = path
        self.tree_item = tree_item

    def run(self):
        try:
            entries = self.handler.list_directory(self.fs, self.inode, self.path)
            self.done.emit(entries, self.tree_item)
        except Exception as exc:
            self.error.emit(f"[ERROR] directory read failed: {exc}")


class ArtifactWorker(QThread):

    done    = pyqtSignal(str, list)    # artifact_id, entries
    log_msg = pyqtSignal(str)
    error   = pyqtSignal(str)

    def __init__(self, artifact_id: str, handler: ImageHandler):
        super().__init__()
        self.artifact_id = artifact_id
        self.handler     = handler

    def run(self):
        runner = ARTIFACT_RUNNERS.get(self.artifact_id)
        if not runner:
            self.error.emit(f"[ERROR] unsupported artifact: {self.artifact_id}")
            return
        try:
            entries = runner(self.handler, self.log_msg.emit)
            self.log_msg.emit(f"[INFO] {self.artifact_id} parsed: {len(entries)} entries")
            self.done.emit(self.artifact_id, entries)
        except Exception as exc:
            self.error.emit(f"[ERROR] {self.artifact_id} parse failed: {exc}")