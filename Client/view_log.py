# coding:utf-8
# python 3.6
# Data_Client for IChain
# J413 

import hashlib
import json
import urllib
import random
import sys
import cgi
import logging
import os

from geventwebsocket.handler import WebSocketHandler
from gevent import pywsgi


import requests
from flask import Flask, jsonify, request, render_template, redirect, url_for
from flask_login import logout_user, UserMixin, login_required, login_user, LoginManager

from wsgiref.simple_server import make_server
from wsgiref.simple_server import WSGIServer


# flask有効化
app = Flask(__name__)

@app.route('/pipe')
def pipe():
    
    # websocket接続要求
    if request.environ.get('wsgi.websocket'):
        # websocket生成
        ws = request.environ['wsgi.websocket']
        
        while True:
            # logファイル読み込み
            with open(os.path.dirname(os.path.abspath(__file__)) +'/logs/' + 'logging'+'.log', "rU") as f:
                data = f.read()
                
            try:
                ws.send(data)
                
            except Exception:
                return 'Error:WebSockeが切断されました。', 400
    

if __name__ == '__main__':
    
    
    
    server = pywsgi.WSGIServer(("0.0.0.0", 8000), app, handler_class=WebSocketHandler)
    server.serve_forever()
    

        
    