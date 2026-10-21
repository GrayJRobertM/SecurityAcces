"""Browser assets must not inherit incorrect Windows MIME registrations."""
import mimetypes
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from app import create_app
from shared_desktop import bridge_request, LocalProxy
from werkzeug.test import Client
from werkzeug.wrappers import Response


class StaticAssetTests(unittest.TestCase):
    def test_css_and_scripts_keep_types_and_bytes_through_shared_proxy(self):
        with tempfile.TemporaryDirectory() as folder:
            app = create_app({'TESTING': True, 'MODE': 'demo', 'DATA_DIR': folder})
            class Pipe:
                def request(self, data):
                    return bridge_request(app, data)
            client = Client(LocalProxy(Pipe()), Response)
            mimetypes.init()
            with patch.dict(mimetypes.types_map, {'.css': 'text/plain', '.js': 'text/plain'}):
                html = client.get('/').get_data(as_text=True)
                assets = re.findall(r'(?:href|src)="(/static/[^"?]+\.(?:css|js))"', html)
                self.assertGreaterEqual(len(assets), 10)
                for path in assets:
                    with self.subTest(path=path):
                        response = client.get(path)
                        self.assertEqual(response.status_code, 200)
                        self.assertEqual(response.mimetype, 'text/css' if path.endswith('.css') else 'text/javascript')
                        self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')
                        self.assertEqual(response.data, (Path(app.static_folder) / path.split('/static/', 1)[1]).read_bytes())
                self.assertEqual(client.get('/static/missing.css').status_code, 404)
                self.assertNotEqual(client.get('/static/missing.css').mimetype, 'text/css')
