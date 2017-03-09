from flask import Flask
import fypFlask
import unittest
from fypFlask import app
from flask_testing import TestCase, LiveServerTestCase
import urllib2


class FlaskTestCase(unittest.TestCase):
    def setUp(self):
        self.tester = app.test_client(self)
        app.config.from_object('config.TestConfig')
        self.baseURL = "http://localhost:5000"
        return app

    def tearDown(self):
        pass


    def test_server_is_up(self):
        response = urllib2.urlopen(self.baseURL)
        self.assertEqual(response.code, 200)


    def test_index_page(self):
        response = self.tester.get('/', follow_redirects=True)

        self.assertEqual(response.status_code, 200)

    def test_about_page(self):
        response = self.tester.get('/about')
        self.assertEqual(response.status_code, 200)

    def test_interfaces_page(self):
        response = self.tester.get('/interfaces',follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    def test_analysis_page(self):
        response = self.tester.get('/analysishub', follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    def test_help_page(self):
        response = self.tester.get('/help')
        self.assertEqual(response.status_code, 200)



class TestNotRenderTemplates(TestCase):

    render_templates = False

    def test_assert_not_render_template(self):
        response = self.client.get("/index")
        assert "" == response.data
        # self.assert_template_used('index.html')

if __name__ == '__main__':
    unittest.main()