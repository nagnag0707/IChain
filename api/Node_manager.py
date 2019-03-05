# coding utf-8
# python 3.6
# NODE_API for IChain
# J413 

import hashlib
import json
import ssl

from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request

class Node_manager:

    def __init__(self):
        # node 保持配列
        self.Nodes = []
        
    def register_node(self, Add, Port):
        # 要素の初期化
        node = {'IP':'', 'PORT':'', 'ACEEPT_ID':''}
        
        # null 判定
        if Add != '' and Port != '': 
            
            for i in self.Nodes:
                print(i)
                if Add == i['IP'] and Port == i['PORT']:
                    return None
            
            node['IP'] = Add
            node['PORT'] = Port
            # uuid を生成
            node['ACEEPT_ID'] = str(uuid4()).replace('-', '')
            
            self.Nodes.append(node)
            
            return node['ACEEPT_ID']
        
        else:
            return False

    def delete_node(self, accept_id):
        response = 'accept_id is not found!'
        
        # accept idと等しいノードを削除
        for i in self.Nodes:
            if i['ACEEPT_ID'] == accept_id:
                self.Nodes.remove(i)
                response = 'accept_id is deleted!'
                break
        
        return response
                
    def get_node(self):
        Nodes = self.Nodes
        res = []
        # ノードリストからACCEPT ID以外を返す
        for i in Nodes:
            ip = i['IP']
            port = i['PORT']
            
            node = {'ip':ip, 'port':port}
            res.append(node)
        return res
        
    def search_node(self, accept_id):
        # accept_id で検索を行いノード情報を返す
        Nodes = self.Nodes
        res = []
        
        for i in Nodes:
            if i['ACEEPT_ID'] == accept_id:
                res.append(i)
        
        return res
        
app = Flask(__name__)

node_identifier = str(uuid4()).replace('-', '')

node_manager = Node_manager()


@app.route('/getNode', methods=['GET'])
def getNode():

    nodes = node_manager.get_node()
    response = {
        'message': "Return Nodes",
        "nodes":nodes
    }
    return jsonify(response), 200
    
@app.route('/get_myNode', methods=['POST'])
def get_myNode():
    values = request.get_json()

    
    accept_id = values.get('accept_id')
    if accept_id is None:
        return "Error: Missing values", 400
    
    res = node_manager.search_node(accept_id)
    
    if res == False:
        return  "Error: Please supply a valid list of nodes", 400
    response = {
        'message': res
    }
    return jsonify(res), 201

@app.route('/register_node', methods=['POST'])
def register_node():
    
    values = request.get_json()
    required = ['ip', 'port']
    
    if not all(k in values for k in required):
        return 'Error: Missing values', 400
    ip = request.remote_addr
    res = node_manager.register_node(ip, values['port'])
    
    if res == None:
        return  "Error: Please delete current nodes", 400
    response = {
        'message': f'register node is success!',
        'accept_id':res
    }
    
    return jsonify(response), 201
 
@app.route('/delete_node', methods=['POST'])
def delete_nodes():
    values = request.get_json()

    accept_id = values.get('accept_id')
    if accept_id is None:
        return "Error: Missing values", 400
    
    res = node_manager.delete_node(accept_id)
    
    if res == False:
        return  "Error: Please supply a valid list of nodes", 400
    response = {
        'message': res
    }
    return jsonify(res), 201
   


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port)
