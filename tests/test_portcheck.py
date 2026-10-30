"""An older FamCheck on the dashboard port is offered for stopping, nothing else. Run: python -m unittest discover tests"""

import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from famcheck import portcheck  # noqa: E402
from famcheck.web import create_server  # noqa: E402

OLD_DASHBOARD = ("import sys; sys.path.insert(0, sys.argv[1]); from pathlib import Path; "
                 "from famcheck.web import create_server; s = create_server(Path(sys.argv[2]), int(sys.argv[3])); "
                 "print('bereit', flush=True); s.serve_forever()")
OTHER_PROGRAM = ("import socket, sys; s = socket.socket(); s.bind(('127.0.0.1', int(sys.argv[1]))); s.listen(); "
                 "print('bereit', flush=True); [s.accept()[0].close() for _ in iter(int, 1)]")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class PortCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cases = Path(self.tmp.name)
        self.port = free_port()
        self.questions = []

    def tearDown(self):
        if getattr(self, "proc", None):
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait()
            self.proc.stdout.close()
        self.tmp.cleanup()

    def occupy(self, code: str, *args):
        self.proc = subprocess.Popen([sys.executable, "-c", code, *map(str, args)], stdout=subprocess.PIPE, text=True)
        self.assertEqual(self.proc.stdout.readline().strip(), "bereit")

    def ask(self, answer):
        def ask(question):
            self.questions.append(question)
            return answer
        return ask

    def test_old_famcheck_is_found_and_stopped_after_yes(self):
        self.occupy(OLD_DASHBOARD, ROOT, self.cases, self.port)
        self.assertTrue(portcheck.famcheck_on_port(self.port))
        # usually the same as proc.pid; a Windows venv python.exe starts the real interpreter as a child
        self.assertIsNotNone(portcheck.listening_pid(self.port))
        server = create_server(self.cases, self.port, ask=self.ask("j"))
        try:
            self.assertIn("älteres FamCheck-Dashboard (Prozess", self.questions[0])
            self.assertIsNotNone(self.proc.wait(timeout=10))  # the old one is gone
            self.assertEqual(server.server_address[1], self.port)
        finally:
            server.server_close()

    def test_no_keeps_the_old_one(self):
        self.occupy(OLD_DASHBOARD, ROOT, self.cases, self.port)
        with self.assertRaises(SystemExit) as ctx:
            create_server(self.cases, self.port, ask=self.ask("n"))
        self.assertIn("schon belegt", str(ctx.exception))
        self.assertIsNone(self.proc.poll())

    def test_other_programs_are_never_offered(self):
        self.occupy(OTHER_PROGRAM, self.port)
        self.assertFalse(portcheck.famcheck_on_port(self.port))
        with self.assertRaises(SystemExit):
            create_server(self.cases, self.port, ask=self.ask("j"))
        self.assertEqual(self.questions, [])
        self.assertIsNone(self.proc.poll())

    def test_without_terminal_only_the_manual_steps(self):
        self.occupy(OLD_DASHBOARD, ROOT, self.cases, self.port)
        with self.assertRaises(SystemExit) as ctx:
            create_server(self.cases, self.port)
        self.assertIn("Stop-Process", str(ctx.exception))
        self.assertIsNone(self.proc.poll())


if __name__ == "__main__":
    unittest.main()
